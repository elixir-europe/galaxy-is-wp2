import pytest

from galaxy.datatypes.binary import Crypt4ghEncryptedArchive
from .util import (
    get_dataset,
    get_input_files,
    get_tmp_path, MockDataset, MockDatasetDataset, MockMetadata,
)

def test_crypt4gh_peek():
    c4gh_loader = Crypt4ghEncryptedArchive()
    with get_input_files("data-complete.c4gh") as input_files:
        dataset = MockDataset(1)
        dataset.file_name = input_files[0]
        dataset.dataset = MockDatasetDataset(dataset.file_name)
        c4gh_loader.set_peek(dataset)
        assert dataset.peek == "Crypt4GH encrypted dataset"
        assert dataset.blurb == "2.8 KB"


def test_crypt4gh_sniff():
    c4gh_loader = Crypt4ghEncryptedArchive()

    input_filenames = ["data-complete.c4gh", "data-header.c4gh", "data-payload.c4gh"]
    with get_input_files(*input_filenames) as input_files:
        c4gh_complete_path, c4gh_header_path, c4gh_payload_path = input_files
        assert c4gh_loader.sniff(c4gh_complete_path) is True
        assert c4gh_loader.sniff(c4gh_header_path) is True
        assert c4gh_loader.sniff(c4gh_payload_path) is False


def _metadata_field_is_set(dataset, field_name):
    return hasattr(dataset.metadata, field_name) and getattr(dataset.metadata, field_name) is not None


def test_crypt4gh_set_meta_not_crypt4gh_header():
    c4gh_loader = Crypt4ghEncryptedArchive()

    input_filenames = ["data-payload.c4gh", "data-complete.c4gh"]
    with get_input_files(*input_filenames) as input_files:
        c4gh_payload_path, c4gh_complete_path = input_files

        dataset = MockDataset(1)
        dataset.file_name = c4gh_payload_path
        dataset.metadata = MockMetadata()

        c4gh_loader.set_meta(dataset=dataset)

        assert not _metadata_field_is_set(dataset, "crypt4gh_header")
        assert not _metadata_field_is_set(dataset, "crypt4gh_metadata_header_sha256")
        assert not _metadata_field_is_set(dataset, "crypt4gh_compute_node_keypair_id")

        dataset.file_name = c4gh_complete_path
        c4gh_loader.set_meta(dataset=dataset)

        assert _metadata_field_is_set(dataset, "crypt4gh_header")
        assert _metadata_field_is_set(dataset, "crypt4gh_metadata_header_sha256")
        assert not _metadata_field_is_set(dataset, "crypt4gh_compute_node_keypair_id")

        c4gh_loader.set_meta(dataset=dataset, crypt4gh_compute_node_keypair_id='cn_keypair_id_123')

        assert _metadata_field_is_set(dataset, "crypt4gh_header")
        assert _metadata_field_is_set(dataset, "crypt4gh_metadata_header_sha256")
        assert _metadata_field_is_set(dataset, "crypt4gh_compute_node_keypair_id")

        with open(c4gh_payload_path, "rb") as payload_file:
            c4gh_loader.set_meta(dataset=dataset, crypt4gh_header=payload_file.read())

        assert not _metadata_field_is_set(dataset, "crypt4gh_header")
        assert not _metadata_field_is_set(dataset, "crypt4gh_metadata_header_sha256")
        assert not _metadata_field_is_set(dataset, "crypt4gh_compute_node_keypair_id")


def test_crypt4gh_set_meta():
    c4gh_loader = Crypt4ghEncryptedArchive()

    ORIG_HEADER_SHA256 = "0491065aa0f4245a7a958fdefc487b9b31327ad594e009ea01d5f8b6b1bb3d8a"
    RECRYPTED_HEADER_SHA256 = "b15c077a3f07f970a04f57c4204fe756307f73b309c922a230696b793d12eee6"

    input_filenames = ["data-complete.c4gh", "data-header.c4gh", "data-header-recrypted.c4gh"]
    with get_input_files(*input_filenames) as input_files:
        c4gh_complete_path, c4gh_orig_header_path, c4gh_recrypted_header_path = input_files

        with open(c4gh_orig_header_path, "rb") as c4gh_orig_header_file:
            c4gh_orig_header = c4gh_orig_header_file.read()

        with open(c4gh_recrypted_header_path, "rb") as c4gh_recrypted_header_file:
            c4gh_recrypted_header = c4gh_recrypted_header_file.read()

        dataset = MockDataset(1)
        dataset.file_name = input_files[0]
        dataset.metadata = MockMetadata()

        c4gh_loader.set_meta(dataset=dataset)

        assert dataset.metadata.crypt4gh_header == c4gh_orig_header
        assert dataset.metadata.crypt4gh_metadata_header_sha256 == ORIG_HEADER_SHA256
        assert dataset.metadata.crypt4gh_dataset_header_sha256 == ORIG_HEADER_SHA256
        assert not _metadata_field_is_set(dataset, 'crypt4gh_compute_node_keypair_id')

        c4gh_loader.set_meta(dataset=dataset, crypt4gh_header=c4gh_recrypted_header)

        assert dataset.metadata.crypt4gh_header == c4gh_recrypted_header
        assert dataset.metadata.crypt4gh_metadata_header_sha256 == RECRYPTED_HEADER_SHA256
        assert dataset.metadata.crypt4gh_dataset_header_sha256 == ORIG_HEADER_SHA256
        assert not _metadata_field_is_set(dataset, 'crypt4gh_compute_node_keypair_id')

        c4gh_loader.set_meta(dataset=dataset, crypt4gh_compute_node_keypair_id='cn_keypair_id_123')
        assert dataset.metadata.crypt4gh_compute_node_keypair_id == 'cn_keypair_id_123'
