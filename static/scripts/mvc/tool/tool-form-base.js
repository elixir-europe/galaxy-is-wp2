define(["utils/utils","utils/deferred","mvc/ui/ui-misc","mvc/form/form-view","mvc/citation/citation-model","mvc/citation/citation-view"],function(a,b,c,d,e,f){return d.extend({initialize:function(a){var c=this;this.deferred=new b,d.prototype.initialize.call(this,a),this.model.get("inputs")?this._buildForm(this.model.attributes):this.deferred.execute(function(a){c._buildModel(a,c.model.attributes,!0)}),this.model.get("listen_to_history")&&parent.Galaxy&&parent.Galaxy.currHistoryPanel&&this.listenTo(parent.Galaxy.currHistoryPanel.collection,"change",function(){c.model.get("onchange")()}),this.$el.on("remove",function(){c._destroy()})},_destroy:function(){var a=this;this.$el.off().hide(),this.deferred.execute(function(){d.prototype.remove.call(a),Galaxy.emit.debug("tool-form-base::_destroy()","Destroy view.")})},_buildForm:function(a){var b=this;this.model.set(a),this.model.set({title:a.title||"<b>"+a.name+"</b> "+a.description+" (Galaxy Version "+a.version+")",operations:!this.model.get("hide_operations")&&this._operations(),onchange:function(){b.deferred.reset(),b.deferred.execute(function(a){b.model.get("postchange")(a,b)})}}),this.model.get("customize")&&this.model.get("customize")(this),this.render(),this.model.get("collapsible")||this.$el.append($("<div/>").addClass("ui-margin-top-large").append(this._footer()))},_buildModel:function(b,d,e){var f=this,g=this.model.attributes;g.version=d.version,g.id=d.id;var h="",i={};g.job_id?h=Galaxy.root+"api/jobs/"+g.job_id+"/build_for_rerun":(h=Galaxy.root+"api/tools/"+g.id+"/build",Galaxy.params&&Galaxy.params.tool_id==g.id&&(i=$.extend({},Galaxy.params),g.version&&(i.tool_version=g.version))),a.get({url:h,data:i,success:function(a){return a.display?(f._buildForm(a),!e&&f.message.update({status:"success",message:"Now you are using '"+g.name+"' version "+g.version+", id '"+g.id+"'.",persistent:!1}),Galaxy.emit.debug("tool-form-base::_buildModel()","Initial tool model ready.",a),void b.resolve()):void(window.location=Galaxy.root)},error:function(a,d){var e=a&&a.err_msg||"Uncaught error.";401==d?window.location=Galaxy.root+"user/login?"+$.param({redirect:Galaxy.root+"?tool_id="+g.id}):f.$el.is(":empty")?f.$el.prepend(new c.Message({message:e,status:"danger",persistent:!0,large:!0}).$el):Galaxy.modal&&Galaxy.modal.show({title:"Tool request failed",body:e,buttons:{Close:function(){Galaxy.modal.hide()}}}),Galaxy.emit.debug("tool-form-base::_buildModel()","Initial tool model request failed.",a),b.reject()}})},_operations:function(){var b=this,d=this.model.attributes,e=new c.ButtonMenu({icon:"fa-cubes",title:!d.narrow&&"Versions"||null,tooltip:"Select another tool version"});if(!d.sustain_version&&d.versions&&d.versions.length>1)for(var f in d.versions){var g=d.versions[f];g!=d.version&&e.addMenu({title:"Switch to "+g,version:g,icon:"fa-cube",onclick:function(){var a=d.id.replace(d.version,this.version),c=this.version;b.deferred.reset(),b.deferred.execute(function(d){b._buildModel(d,{id:a,version:c})})}})}else e.$el.hide();var h=new c.ButtonMenu({icon:"fa-caret-down",title:!d.narrow&&"Options"||null,tooltip:"View available options"});return d.biostar_url&&(h.addMenu({icon:"fa-question-circle",title:"Question?",onclick:function(){window.open(d.biostar_url+"/p/new/post/")}}),h.addMenu({icon:"fa-search",title:"Search",onclick:function(){window.open(d.biostar_url+"/local/search/page/?q="+d.name)}})),h.addMenu({icon:"fa-share",title:"Share",onclick:function(){prompt("Copy to clipboard: Ctrl+C, Enter",window.location.origin+Galaxy.root+"root?tool_id="+d.id)}}),Galaxy.user&&Galaxy.user.get("is_admin")&&(h.addMenu({icon:"fa-download",title:"Download",onclick:function(){window.location.href=Galaxy.root+"api/tools/"+d.id+"/download"}}),h.addMenu({icon:"fa-refresh",title:"Reload XML",onclick:function(){a.get({url:Galaxy.root+"api/tools/"+d.id+"/reload",success:function(){b.message.update({persistent:!1,message:"Tool XML has been reloaded.",status:"success"})},error:function(a){b.message.update({persistent:!1,message:a.err_msg,status:"danger"})}})}})),d.requirements&&d.requirements.length>0&&h.addMenu({icon:"fa-info-circle",title:"Requirements",onclick:function(){!this.requirements_visible||b.portlet.collapsed?(this.requirements_visible=!0,b.portlet.expand(),b.message.update({persistent:!0,message:b._templateRequirements(d),status:"info"})):(this.requirements_visible=!1,b.message.update({message:""}))}}),d.sharable_url&&h.addMenu({icon:"fa-external-link",title:"See in Tool Shed",onclick:function(){window.open(d.sharable_url)}}),$.getJSON("/api/webhooks/tool-menu/all",function(a){_.each(a,function(a){a.activate&&a.config.function&&h.addMenu({icon:a.config.icon,title:a.config.title,onclick:function(){var b=new Function("options",a.config.function);b(d)}})})}),{menu:h,versions:e}},_footer:function(){var a=this.model.attributes,b=$("<div/>").append(this._templateHelp(a));if(a.citations){var c=$("<div/>"),d=new e.ToolCitationCollection;d.tool_id=a.id;var g=new f.CitationListView({el:c,collection:d});g.render(),d.fetch(),b.append(c)}return b},_templateHelp:function(a){var b=$("<div/>").addClass("ui-form-help").append(a.help);return b.find("a").attr("target","_blank"),b},_templateRequirements:function(a){var b=a.requirements.length;if(b>0){var c="This tool requires ";_.each(a.requirements,function(a,d){c+=a.name+(a.version?" (Version "+a.version+")":"")+(b-2>d?", ":d==b-2?" and ":"")});var d=$("<a/>").attr("target","_blank").attr("href","https://galaxyproject.org/tools/requirements/").text("here");return $("<span/>").append(c+". Click ").append(d).append(" for more information.")}return"No requirements found."}})});
//# sourceMappingURL=../../../maps/mvc/tool/tool-form-base.js.map