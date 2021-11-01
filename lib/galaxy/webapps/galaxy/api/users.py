"""
API operations on User objects.
"""
import copy
import json
import logging
import re

from markupsafe import escape
from sqlalchemy import (
    false,
    or_,
    true
)

from galaxy import (
    exceptions,
    util,
    web
)
from galaxy.exceptions import ObjectInvalid
from galaxy.managers import (
    api_keys,
    users
)
from galaxy.managers.context import ProvidesUserContext
from galaxy.model import User, UserAddress
from galaxy.security.validate_user_input import (
    validate_email,
    validate_password,
    validate_publicname
)
from galaxy.tool_util.toolbox.filters import FilterFactory
from galaxy.util import (
    docstring_trim,
    listify
)
from galaxy.web import (
    expose_api,
    expose_api_anonymous
)
from galaxy.web.form_builder import AddressField
from galaxy.webapps.base.controller import (
    BaseUIController,
    UsesFormDefinitionsMixin,
    UsesTagsMixin
)
from galaxy.webapps.base.webapp import GalaxyWebTransaction
from . import BaseGalaxyAPIController, depends

log = logging.getLogger(__name__)


class UserAPIController(BaseGalaxyAPIController, UsesTagsMixin, BaseUIController, UsesFormDefinitionsMixin):
    user_manager: users.UserManager = depends(users.UserManager)
    user_serializer: users.UserSerializer = depends(users.UserSerializer)
    user_deserializer: users.UserDeserializer = depends(users.UserDeserializer)
    api_key_manager: api_keys.ApiKeyManager = depends(api_keys.ApiKeyManager)

    @expose_api
    def index(self, trans: ProvidesUserContext, deleted='False', f_email=None, f_name=None, f_any=None, **kwd):
        """
        GET /api/users
        GET /api/users/deleted
        Displays a collection (list) of users.

        :param deleted: (optional) If true, show deleted users
        :type  deleted: bool

        :param f_email: (optional) An email address to filter on. (Non-admin
                        users can only use this if ``expose_user_email`` is ``True`` in
                        galaxy.ini)
        :type  f_email: str

        :param f_name: (optional) A username to filter on. (Non-admin users
                       can only use this if ``expose_user_name`` is ``True`` in
                       galaxy.ini)
        :type  f_name: str

        :param f_any: (optional) Filter on username OR email. (Non-admin users
                       can use this, the email filter and username filter will
                       only be active if their corresponding ``expose_user_*`` is
                       ``True`` in galaxy.ini)
        :type  f_any: str
        """
        rval = []
        query = trans.sa_session.query(User)
        deleted = util.string_as_bool(deleted)

        if f_email and (trans.user_is_admin or trans.app.config.expose_user_email):
            query = query.filter(User.email.like(f"%{f_email}%"))

        if f_name and (trans.user_is_admin or trans.app.config.expose_user_name):
            query = query.filter(User.username.like(f"%{f_name}%"))

        if f_any:
            if trans.user_is_admin:
                query = query.filter(or_(
                    User.email.like(f"%{f_any}%"),
                    User.username.like(f"%{f_any}%")
                ))
            else:
                if trans.app.config.expose_user_email and trans.app.config.expose_user_name:
                    query = query.filter(or_(
                        User.email.like(f"%{f_any}%"),
                        User.username.like(f"%{f_any}%")
                    ))
                elif trans.app.config.expose_user_email:
                    query = query.filter(User.email.like(f"%{f_any}%"))
                elif trans.app.config.expose_user_name:
                    query = query.filter(User.username.like(f"%{f_any}%"))

        if deleted:
            # only admins can see deleted users
            if not trans.user_is_admin:
                return []
            query = query.filter(User.table.c.deleted == true())
        else:
            # special case: user can see only their own user
            # special case2: if the galaxy admin has specified that other user email/names are
            #   exposed, we don't want special case #1
            if not trans.user_is_admin and not trans.app.config.expose_user_name and not trans.app.config.expose_user_email:
                item = trans.user.to_dict(value_mapper={'id': trans.security.encode_id})
                return [item]
            query = query.filter(User.table.c.deleted == false())
        for user in query:
            item = user.to_dict(value_mapper={'id': trans.security.encode_id})
            # If NOT configured to expose_email, do not expose email UNLESS the user is self, or
            # the user is an admin
            if user is not trans.user and not trans.user_is_admin:
                expose_keys = ["id"]
                if trans.app.config.expose_user_name:
                    expose_keys.append("username")
                if trans.app.config.expose_user_email:
                    expose_keys.append("email")
                new_item = {}
                for key, value in item.items():
                    if key in expose_keys:
                        new_item[key] = value
                item = new_item

            # TODO: move into api_values
            rval.append(item)
        return rval

    @expose_api_anonymous
    def show(self, trans: ProvidesUserContext, id, deleted='False', **kwd):
        """
        GET /api/users/{encoded_id}
        GET /api/users/deleted/{encoded_id}
        GET /api/users/current
        Displays information about a user.
        """
        deleted = util.string_as_bool(deleted)
        try:
            # user is requesting data about themselves
            if id == "current":
                # ...and is anonymous - return usage and quota (if any)
                if not trans.user:
                    item = self.anon_user_api_value(trans)
                    return item

                # ...and is logged in - return full
                else:
                    user = trans.user
            else:
                user = self.get_user(trans, id, deleted=deleted)
            # check that the user is requesting themselves (and they aren't del'd) unless admin
            if not trans.user_is_admin:
                assert trans.user == user
                assert not user.deleted
        except exceptions.ItemDeletionException:
            raise
        except Exception:
            raise exceptions.RequestParameterInvalidException('Invalid user id specified', id=id)
        return self.user_serializer.serialize_to_view(user, view='detailed')

    @expose_api
    def create(self, trans: GalaxyWebTransaction, payload: dict, **kwd):
        """
        POST /api/users
        Creates a new Galaxy user.
        """
        if not trans.app.config.allow_user_creation and not trans.user_is_admin:
            raise exceptions.ConfigDoesNotAllowException('User creation is not allowed in this Galaxy instance')
        if trans.app.config.use_remote_user and trans.user_is_admin:
            user = trans.get_or_create_remote_user(remote_user_email=payload['remote_user_email'])
        elif trans.user_is_admin:
            username = payload['username']
            email = payload['email']
            password = payload['password']
            message = "\n".join((validate_email(trans, email),
                                 validate_password(trans, password, password),
                                 validate_publicname(trans, username))).rstrip()
            if message:
                raise exceptions.RequestParameterInvalidException(message)
            else:
                user = self.user_manager.create(email=email, username=username, password=password)
        else:
            raise exceptions.NotImplemented()
        item = user.to_dict(view='element', value_mapper={'id': trans.security.encode_id,
                                                          'total_disk_usage': float})
        return item

    @expose_api
    def update(self, trans: ProvidesUserContext, id: str, payload: dict, **kwd):
        """
        update( self, trans, id, payload, **kwd )
        * PUT /api/users/{id}
            updates the values for the item with the given ``id``

        :type id: str
        :param id: the encoded id of the item to update
        :type payload: dict
        :param payload: a dictionary of new attribute values

        :rtype: dict
        :returns: an error object if an error occurred or a dictionary containing
            the serialized item after any changes
        """
        current_user = trans.user
        user_to_update = self.user_manager.by_id(self.decode_id(id))

        # only allow updating other users if they're admin
        editing_someone_else = current_user != user_to_update
        is_admin = self.user_manager.is_admin(current_user)
        if editing_someone_else and not is_admin:
            raise exceptions.InsufficientPermissionsException('You are not allowed to update that user', id=id)

        self.user_deserializer.deserialize(user_to_update, payload, user=current_user, trans=trans)
        return self.user_serializer.serialize_to_view(user_to_update, view='detailed')

    @expose_api
    def delete(self, trans, id, **kwd):
        """
        DELETE /api/users/{id}
        delete the user with the given ``id``
        Functionality restricted based on admin status

        :param id: the encoded id of the user to delete
        :type  id: str

        :param purge: (optional) if True, purge the user
        :type  purge: bool
        """
        user_to_update = self.user_manager.by_id(self.decode_id(id))
        if trans.user_is_admin:
            purge = util.string_as_bool(kwd.get('purge', False))
            if purge:
                log.debug("Purging user %s", user_to_update)
                self.user_manager.purge(user_to_update)
            else:
                self.user_manager.delete(user_to_update)
        else:
            if trans.user == user_to_update:
                self.user_manager.delete(user_to_update)
            else:
                raise exceptions.InsufficientPermissionsException('You may only delete your own account.', id=id)
        return self.user_serializer.serialize_to_view(user_to_update, view='detailed')

    @web.require_admin
    @expose_api
    def undelete(self, trans, id, **kwd):
        """
        POST /api/users/deleted/{id}/undelete
        Undelete the user with the given ``id``

        :param id: the encoded id of the user to be undeleted
        :type  id: str
        """
        user = self.get_user(trans, id)
        self.user_manager.undelete(user)
        return self.user_serializer.serialize_to_view(user, view='detailed')

    # TODO: move to more basal, common resource than this
    def anon_user_api_value(self, trans):
        """Return data for an anonymous user, truncated to only usage and quota_percent"""
        usage = trans.app.quota_agent.get_usage(trans)
        percent = trans.app.quota_agent.get_percent(trans=trans, usage=usage)
        return {'total_disk_usage': int(usage),
                'nice_total_disk_usage': util.nice_size(usage),
                'quota_percent': percent}

    def _get_extra_user_preferences(self, trans):
        """
        Reads the file user_preferences_extra_conf.yml to display
        admin defined user informations
        """
        return trans.app.config.user_preferences_extra['preferences']

    def _build_extra_user_pref_inputs(self, preferences, user):
        """
        Build extra user preferences inputs list.
        Add values to the fields if present
        """
        if not preferences:
            return []
        extra_pref_inputs = list()
        # Build sections for different categories of inputs
        for item, value in preferences.items():
            if value is not None:
                input_fields = copy.deepcopy(value["inputs"])
                for input in input_fields:
                    help = input.get('help', '')
                    required = 'Required' if util.string_as_bool(input.get('required')) else ''
                    if help:
                        input['help'] = f"{help} {required}"
                    else:
                        input['help'] = required
                    field = f"{item}|{input['name']}"
                    for data_item in user.extra_preferences:
                        if field in data_item:
                            input['value'] = user.extra_preferences[data_item]
                extra_pref_inputs.append({'type': 'section', 'title': value['description'], 'name': item, 'expanded': True, 'inputs': input_fields})
        return extra_pref_inputs

    @expose_api
    def get_information(self, trans, id, **kwd):
        """
        GET /api/users/{id}/information/inputs
        Return user details such as username, email, addresses etc.

        :param id: the encoded id of the user
        :type  id: str
        """
        user = self._get_user(trans, id)
        email = user.email
        username = user.username
        inputs = list()
        inputs.append({
            'id': 'email_input',
            'name': 'email',
            'type': 'text',
            'label': 'Email address',
            'value': email,
            'help': 'If you change your email address you will receive an activation link in the new mailbox and you have to activate your account by visiting it.'})
        if trans.webapp.name == 'galaxy':
            inputs.append({
                'id': 'name_input',
                'name': 'username',
                'type': 'text',
                'label': 'Public name',
                'value': username,
                'help': 'Your public name is an identifier that will be used to generate addresses for information you share publicly. Public names must be at least three characters in length and contain only lower-case letters, numbers, and the "-" character.'})
            info_form_models = self.get_all_forms(trans, filter=dict(deleted=False), form_type=trans.app.model.FormDefinition.types.USER_INFO)
            if info_form_models:
                info_form_id = trans.security.encode_id(user.values.form_definition.id) if user.values else None
                info_field = {
                    'type': 'conditional',
                    'name': 'info',
                    'cases': [],
                    'test_param': {
                        'name': 'form_id',
                        'label': 'User type',
                        'type': 'select',
                        'value': info_form_id,
                        'help': '',
                        'data': []
                    }
                }
                for f in info_form_models:
                    values = None
                    if info_form_id == trans.security.encode_id(f.id) and user.values:
                        values = user.values.content
                    info_form = f.to_dict(user=user, values=values, security=trans.security)
                    info_field['test_param']['data'].append({'label': info_form['name'], 'value': info_form['id']})
                    info_field['cases'].append({'value': info_form['id'], 'inputs': info_form['inputs']})
                inputs.append(info_field)

            address_inputs = [{'type': 'hidden', 'name': 'id', 'hidden': True}]
            for field in AddressField.fields():
                address_inputs.append({'type': 'text', 'name': field[0], 'label': field[1], 'help': field[2]})
            address_repeat = {'title': 'Address', 'name': 'address', 'type': 'repeat', 'inputs': address_inputs, 'cache': []}
            address_values = [address.to_dict(trans) for address in user.addresses]
            for address in address_values:
                address_cache = []
                for input in address_inputs:
                    input_copy = input.copy()
                    input_copy['value'] = address.get(input['name'])
                    address_cache.append(input_copy)
                address_repeat['cache'].append(address_cache)
            inputs.append(address_repeat)

            # Build input sections for extra user preferences
            extra_user_pref = self._build_extra_user_pref_inputs(self._get_extra_user_preferences(trans), user)
            for item in extra_user_pref:
                inputs.append(item)
        else:
            if user.active_repositories:
                inputs.append(dict(id='name_input', name='username', label='Public name:', type='hidden', value=username, help='You cannot change your public name after you have created a repository in this tool shed.'))
            else:
                inputs.append(dict(id='name_input', name='username', label='Public name:', type='text', value=username, help='Your public name provides a means of identifying you publicly within this tool shed. Public names must be at least three characters in length and contain only lower-case letters, numbers, and the "-" character. You cannot change your public name after you have created a repository in this tool shed.'))
        return {
            'email': email,
            'username': username,
            'addresses': [address.to_dict(trans) for address in user.addresses],
            'inputs': inputs,
        }

    @expose_api
    def set_information(self, trans, id, payload=None, **kwd):
        """
        PUT /api/users/{id}/information/inputs
        Save a user's email, username, addresses etc.

        :param id: the encoded id of the user
        :type  id: str

        :param payload: data with new settings
        :type  payload: dict
        """
        payload = payload or {}
        user = self._get_user(trans, id)
        # Update email
        if 'email' in payload:
            email = payload.get('email')
            message = validate_email(trans, email, user)
            if message:
                raise exceptions.RequestParameterInvalidException(message)
            if user.email != email:
                # Update user email and user's private role name which must match
                private_role = trans.app.security_agent.get_private_user_role(user)
                private_role.name = email
                private_role.description = f"Private role for {email}"
                user.email = email
                trans.sa_session.add(user)
                trans.sa_session.add(private_role)
                trans.sa_session.flush()
                if trans.app.config.user_activation_on:
                    # Deactivate the user if email was changed and activation is on.
                    user.active = False
                    if self.user_manager.send_activation_email(trans, user.email, user.username):
                        message = 'The login information has been updated with the changes.<br>Verification email has been sent to your new email address. Please verify it by clicking the activation link in the email.<br>Please check your spam/trash folder in case you cannot find the message.'
                    else:
                        message = 'Unable to send activation email, please contact your local Galaxy administrator.'
                        if trans.app.config.error_email_to is not None:
                            message += f' Contact: {trans.app.config.error_email_to}'
                        raise exceptions.InternalServerError(message)
        # Update public name
        if 'username' in payload:
            username = payload.get('username')
            message = validate_publicname(trans, username, user)
            if message:
                raise exceptions.RequestParameterInvalidException(message)
            if user.username != username:
                user.username = username
        # Update user custom form
        user_info_form_id = payload.get('info|form_id')
        if user_info_form_id:
            prefix = 'info|'
            user_info_form = trans.sa_session.query(trans.app.model.FormDefinition).get(trans.security.decode_id(user_info_form_id))
            user_info_values = {}
            for item in payload:
                if item.startswith(prefix):
                    user_info_values[item[len(prefix):]] = payload[item]
            form_values = trans.model.FormValues(user_info_form, user_info_values)
            trans.sa_session.add(form_values)
            user.values = form_values

        # Update values for extra user preference items
        extra_user_pref_data = dict()
        extra_pref_keys = self._get_extra_user_preferences(trans)
        if extra_pref_keys is not None:
            for key in extra_pref_keys:
                key_prefix = f"{key}|"
                for item in payload:
                    if item.startswith(key_prefix):
                        # Show error message if the required field is empty
                        if payload[item] == "":
                            # Raise an exception when a required field is empty while saving the form
                            keys = item.split("|")
                            section = extra_pref_keys[keys[0]]
                            for input in section['inputs']:
                                if input['name'] == keys[1] and input['required']:
                                    raise exceptions.ObjectAttributeMissingException("Please fill the required field")
                        extra_user_pref_data[item] = payload[item]
            user.preferences["extra_user_preferences"] = json.dumps(extra_user_pref_data)

        # Update user addresses
        address_dicts = {}
        address_count = 0
        for item in payload:
            match = re.match(r'^address_(?P<index>\d+)\|(?P<attribute>\S+)', item)
            if match:
                groups = match.groupdict()
                index = int(groups['index'])
                attribute = groups['attribute']
                address_dicts[index] = address_dicts.get(index) or {}
                address_dicts[index][attribute] = payload[item]
                address_count = max(address_count, index + 1)
        user.addresses = []
        for index in range(0, address_count):
            d = address_dicts[index]
            if d.get('id'):
                try:
                    user_address = trans.sa_session.query(UserAddress).get(trans.security.decode_id(d['id']))
                except Exception as e:
                    raise exceptions.ObjectNotFound(f"Failed to access user address ({d['id']}). {e}")
            else:
                user_address = UserAddress()
                trans.log_event('User address added')
            for field in AddressField.fields():
                if str(field[2]).lower() == 'required' and not d.get(field[0]):
                    raise exceptions.ObjectAttributeMissingException(f'Address {index + 1}: {field[1]} ({field[0]}) required.')
                setattr(user_address, field[0], str(d.get(field[0], '')))
            user_address.user = user
            user.addresses.append(user_address)
            trans.sa_session.add(user_address)
        trans.sa_session.add(user)
        trans.sa_session.flush()
        trans.log_event('User information added')
        return {'message': 'User information has been saved.'}

    @expose_api
    def set_favorite(self, trans, id, object_type, payload=None, **kwd):
        """Add the object to user's favorites
        PUT /api/users/{id}/favorites/{object_type}

        :param id: the encoded id of the user
        :type  id: str
        :param object_type: the object type that users wants to favorite
        :type  object_type: str
        :param object_id: the id of an object that users wants to favorite
        :type  object_id: str
        """
        payload = payload or {}
        self._validate_favorite_object_type(object_type)
        user = self._get_user(trans, id)
        favorites = json.loads(user.preferences['favorites']) if 'favorites' in user.preferences else {}
        if object_type == 'tools':
            tool_id = payload.get('object_id')
            tool = self.app.toolbox.get_tool(tool_id)
            if not tool:
                raise exceptions.ObjectNotFound(f"Could not find tool with id '{tool_id}'.")
            if not tool.allow_user_access(user):
                raise exceptions.AuthenticationFailed(f"Access denied for tool with id '{tool_id}'.")
            if 'tools' in favorites:
                favorite_tools = favorites['tools']
            else:
                favorite_tools = []
            if tool_id not in favorite_tools:
                favorite_tools.append(tool_id)
                favorites['tools'] = favorite_tools
                user.preferences['favorites'] = json.dumps(favorites)
                trans.sa_session.flush()
        return favorites

    @expose_api
    def remove_favorite(self, trans, id, object_type, object_id, payload=None, **kwd):
        """Remove the object from user's favorites
        DELETE /api/users/{id}/favorites/{object_type}/{object_id:.*?}

        :param id: the encoded id of the user
        :type  id: str
        :param object_type: the object type that users wants to favorite
        :type  object_type: str
        :param object_id: the id of an object that users wants to remove from favorites
        :type  object_id: str
        """
        payload = payload or {}
        self._validate_favorite_object_type(object_type)
        user = self._get_user(trans, id)
        favorites = json.loads(user.preferences['favorites']) if 'favorites' in user.preferences else {}
        if object_type == 'tools':
            if 'tools' in favorites:
                favorite_tools = favorites['tools']
                if object_id in favorite_tools:
                    del favorite_tools[favorite_tools.index(object_id)]
                    favorites['tools'] = favorite_tools
                    user.preferences['favorites'] = json.dumps(favorites)
                    trans.sa_session.flush()
                else:
                    raise exceptions.ObjectNotFound('Given object is not in the list of favorites')
        return favorites

    def _validate_favorite_object_type(self, object_type):
        if object_type in ['tools']:
            pass
        else:
            raise exceptions.ObjectAttributeInvalidException(f"This type is not supported. Given object_type: {object_type}")

    @expose_api
    def get_password(self, trans, id, payload=None, **kwd):
        """
        Return available password inputs.
        """
        payload = payload or {}
        return {'inputs': [{'name': 'current', 'type': 'password', 'label': 'Current password'},
                           {'name': 'password', 'type': 'password', 'label': 'New password'},
                           {'name': 'confirm', 'type': 'password', 'label': 'Confirm password'}]}

    @expose_api
    def set_password(self, trans, id, payload=None, **kwd):
        """
        Allows to the logged-in user to change own password.
        """
        payload = payload or {}
        user, message = self.user_manager.change_password(trans, id=id, **payload)
        if user is None:
            raise exceptions.AuthenticationRequired(message)
        return {"message": "Password has been changed."}

    @expose_api
    def get_permissions(self, trans, id, payload=None, **kwd):
        """
        Get the user's default permissions for the new histories
        """
        payload = payload or {}
        user = self._get_user(trans, id)
        roles = user.all_roles()
        inputs = []
        for index, action in trans.app.model.Dataset.permitted_actions.items():
            inputs.append({'type': 'select',
                           'multiple': True,
                           'optional': True,
                           'name': index,
                           'label': action.action,
                           'help': action.description,
                           'options': list({(r.name, r.id) for r in roles}),
                           'value': [a.role.id for a in user.default_permissions if a.action == action.action]})
        return {'inputs': inputs}

    @expose_api
    def set_permissions(self, trans, id, payload=None, **kwd):
        """
        Set the user's default permissions for the new histories
        """
        payload = payload or {}
        user = self._get_user(trans, id)
        permissions = {}
        for index, action in trans.app.model.Dataset.permitted_actions.items():
            action_id = trans.app.security_agent.get_action(action.action).action
            permissions[action_id] = [trans.sa_session.query(trans.app.model.Role).get(x) for x in (payload.get(index) or [])]
        trans.app.security_agent.user_set_default_permissions(user, permissions)
        return {'message': 'Permissions have been saved.'}

    @expose_api
    def get_toolbox_filters(self, trans, id, payload=None, **kwd):
        """
        API call for fetching toolbox filters data. Toolbox filters are specified in galaxy.ini.
        The user can activate them and the choice is stored in user_preferences.
        """
        payload = payload or {}
        user = self._get_user(trans, id)
        filter_types = self._get_filter_types(trans)
        saved_values = {}
        for name, value in user.preferences.items():
            if name in filter_types:
                saved_values[name] = listify(value, do_strip=True)
        inputs = [{
            'type': 'hidden',
            'name': 'helptext',
            'label': 'In this section you may enable or disable Toolbox filters. Please contact your admin to configure filters as necessary.'
        }]
        errors = {}
        factory = FilterFactory(trans.app.toolbox)
        for filter_type in filter_types:
            self._add_filter_inputs(factory, filter_types, inputs, errors, filter_type, saved_values)
        return {'inputs': inputs, 'errors': errors}

    @expose_api
    def set_toolbox_filters(self, trans, id, payload=None, **kwd):
        """
        API call to update toolbox filters data.
        """
        payload = payload or {}
        user = self._get_user(trans, id)
        filter_types = self._get_filter_types(trans)
        for filter_type in filter_types:
            new_filters = []
            for prefixed_name in payload:
                if util.string_as_bool(payload.get(prefixed_name)) and prefixed_name.startswith(filter_type):
                    prefix = f"{filter_type}|"
                    new_filters.append(prefixed_name[len(prefix):])
            user.preferences[filter_type] = ','.join(new_filters)
        trans.sa_session.add(user)
        trans.sa_session.flush()
        return {'message': 'Toolbox filters have been saved.'}

    def _add_filter_inputs(self, factory, filter_types, inputs, errors, filter_type, saved_values):
        filter_inputs = list()
        filter_values = saved_values.get(filter_type, [])
        filter_config = filter_types[filter_type]['config']
        filter_title = filter_types[filter_type]['title']
        for filter_name in filter_config:
            function = factory.build_filter_function(filter_name)
            if function is None:
                errors[f'{filter_type}|{filter_name}'] = 'Filter function not found.'

            short_description, description = None, None
            doc_string = docstring_trim(function.__doc__)
            split = doc_string.split('\n\n')
            if split:
                short_description = split[0]
                if len(split) > 1:
                    description = split[1]
            else:
                log.warning(f'No description specified in the __doc__ string for {filter_name}.')

            filter_inputs.append({
                'type': 'boolean',
                'name': filter_name,
                'label': short_description or filter_name,
                'help': description or 'No description available.',
                'value': 'true' if filter_name in filter_values else 'false'
            })
        if filter_inputs:
            inputs.append({'type': 'section', 'title': filter_title, 'name': filter_type, 'expanded': True, 'inputs': filter_inputs})

    def _get_filter_types(self, trans):
        return {'toolbox_tool_filters': {'title': 'Tools', 'config': trans.app.config.user_tool_filters},
                'toolbox_section_filters': {'title': 'Sections', 'config': trans.app.config.user_tool_section_filters},
                'toolbox_label_filters': {'title': 'Labels', 'config': trans.app.config.user_tool_label_filters}}

    @expose_api
    def api_key(self, trans, id, payload=None, **kwd):
        """
        Create API key.
        """
        payload = payload or {}
        user = self._get_user(trans, id)
        return self.api_key_manager.create_api_key(user)

    @expose_api
    def get_or_create_api_key(self, trans, id, payload=None, **kwd):
        """
        Unified 'get or create' for API key
        """
        payload = payload or {}
        user = self._get_user(trans, id)
        return self.api_key_manager.get_or_create_api_key(user)

    @expose_api
    def get_api_key(self, trans, id, payload=None, **kwd):
        """
        Get API key inputs.
        """
        payload = payload or {}
        user = self._get_user(trans, id)
        return self._build_inputs_api_key(user)

    @expose_api
    def set_api_key(self, trans, id, payload=None, **kwd):
        """
        Get API key inputs with new API key.
        """
        payload = payload or {}
        user = self._get_user(trans, id)
        self.api_key_manager.create_api_key(user)
        return self._build_inputs_api_key(user, message='Generated a new web API key.')

    def _build_inputs_api_key(self, user, message=''):
        """
        Build API key inputs.
        """
        inputs = [{'name': 'api-key',
                   'type': 'text',
                   'label': 'Current API key:',
                   'value': user.api_keys[0].key if user.api_keys else 'Not available.',
                   'readonly': True,
                   'help': ' An API key will allow you to access via web API. Please note that this key acts as an alternate means to access your account and should be treated with the same care as your login password.'}]
        return {'message': message, 'inputs': inputs}

    @expose_api
    def get_custom_builds(self, trans, id, payload=None, **kwd):
        """
        GET /api/users/{id}/custom_builds
        Returns collection of custom builds.

        :param id: the encoded id of the user
        :type  id: str
        """
        payload = payload or {}
        user = self._get_user(trans, id)
        dbkeys = json.loads(user.preferences['dbkeys']) if 'dbkeys' in user.preferences else {}
        valid_dbkeys = {}
        update = False
        for key, dbkey in dbkeys.items():
            if 'count' not in dbkey and 'linecount' in dbkey:
                chrom_count_dataset = trans.sa_session.query(trans.app.model.HistoryDatasetAssociation).get(dbkey['linecount'])
                if chrom_count_dataset and not chrom_count_dataset.deleted and chrom_count_dataset.state == trans.app.model.HistoryDatasetAssociation.states.OK:
                    chrom_count = int(open(chrom_count_dataset.file_name).readline())
                    dbkey['count'] = chrom_count
                    valid_dbkeys[key] = dbkey
                    update = True
            else:
                valid_dbkeys[key] = dbkey
        if update:
            user.preferences['dbkeys'] = json.dumps(valid_dbkeys)
        dbkey_collection = []
        for key, attributes in valid_dbkeys.items():
            attributes['id'] = key
            dbkey_collection.append(attributes)
        return dbkey_collection

    @expose_api
    def add_custom_builds(self, trans, id, key, payload=None, **kwd):
        """
        PUT /api/users/{id}/custom_builds/{key}
        Add new custom build.

        :param id: the encoded id of the user
        :type  id: str

        :param id: custom build key
        :type  id: str

        :param payload: data with new build details
        :type  payload: dict
        """
        payload = payload or {}
        user = self._get_user(trans, id)
        dbkeys = json.loads(user.preferences['dbkeys']) if 'dbkeys' in user.preferences else {}
        name = payload.get('name')
        len_type = payload.get('len|type')
        len_value = payload.get('len|value')
        if len_type not in ['file', 'fasta', 'text'] or not len_value:
            raise exceptions.RequestParameterInvalidException('Please specify a valid data source type.')
        if not name or not key:
            raise exceptions.RequestParameterMissingException('You must specify values for all the fields.')
        elif key in dbkeys:
            raise exceptions.DuplicatedIdentifierException('There is already a custom build with that key. Delete it first if you want to replace it.')
        else:
            # Have everything needed; create new build.
            build_dict = {'name': name}
            if len_type in ['text', 'file']:
                # Create new len file
                new_len = trans.app.model.HistoryDatasetAssociation(extension='len', create_dataset=True, sa_session=trans.sa_session)
                trans.sa_session.add(new_len)
                new_len.name = name
                new_len.visible = False
                new_len.state = trans.app.model.Job.states.OK
                new_len.info = 'custom build .len file'
                try:
                    trans.app.object_store.create(new_len.dataset)
                except ObjectInvalid:
                    raise exceptions.InternalServerError('Unable to create output dataset: object store is full.')
                trans.sa_session.flush()
                counter = 0
                lines_skipped = 0
                with open(new_len.file_name, 'w') as f:
                    # LEN files have format:
                    #   <chrom_name><tab><chrom_length>
                    for line in len_value.split('\n'):
                        # Splits at the last whitespace in the line
                        lst = line.strip().rsplit(None, 1)
                        if not lst or len(lst) < 2:
                            lines_skipped += 1
                            continue
                        chrom, length = lst[0], lst[1]
                        try:
                            length = int(length)
                        except ValueError:
                            lines_skipped += 1
                            continue
                        if chrom != escape(chrom):
                            build_dict['message'] = 'Invalid chromosome(s) with HTML detected and skipped.'
                            lines_skipped += 1
                            continue
                        counter += 1
                        f.write(f'{chrom}\t{length}\n')
                build_dict['len'] = new_len.id
                build_dict['count'] = counter
            else:
                build_dict['fasta'] = trans.security.decode_id(len_value)
                dataset = trans.sa_session.query(trans.app.model.HistoryDatasetAssociation).get(build_dict['fasta'])
                try:
                    new_len = dataset.get_converted_dataset(trans, 'len')
                    new_linecount = new_len.get_converted_dataset(trans, 'linecount')
                    build_dict['len'] = new_len.id
                    build_dict['linecount'] = new_linecount.id
                except Exception:
                    raise exceptions.ToolExecutionError('Failed to convert dataset.')
            dbkeys[key] = build_dict
            user.preferences['dbkeys'] = json.dumps(dbkeys)
            trans.sa_session.flush()
            return build_dict

    @expose_api
    def delete_custom_builds(self, trans, id, key, payload=None, **kwd):
        """
        DELETE /api/users/{id}/custom_builds/{key}
        Delete a custom build.

        :param id: the encoded id of the user
        :type  id: str

        :param id: custom build key to be deleted
        :type  id: str
        """
        payload = payload or {}
        user = self._get_user(trans, id)
        dbkeys = json.loads(user.preferences['dbkeys']) if 'dbkeys' in user.preferences else {}
        if key and key in dbkeys:
            del dbkeys[key]
            user.preferences['dbkeys'] = json.dumps(dbkeys)
            trans.sa_session.flush()
            return {'message': f'Deleted {key}.'}
        else:
            raise exceptions.ObjectNotFound(f'Could not find and delete build ({key}).')

    def _get_user(self, trans, id):
        user = self.get_user(trans, id)
        if not user:
            raise exceptions.RequestParameterInvalidException(f'Invalid user ({id}).')
        if user != trans.user and not trans.user_is_admin:
            raise exceptions.InsufficientPermissionsException('Access denied.')
        return user
