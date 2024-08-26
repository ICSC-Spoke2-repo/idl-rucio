from abc import ABCMeta, abstractmethod
from typing import TYPE_CHECKING, Literal

import json 
import operator

from rucio.common import exception
from rucio.core.did_meta_plugins.did_meta_plugin_interface import DidMetaPlugin
from rucio.core.did_meta_plugins.filter_engine import FilterEngine
from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType
from rucio.db.sqla.session import read_session, stream_session, transactional_session
from rucio.db.sqla.util import json_implemented

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import Any, Optional, Union

    from sqlalchemy.orm import Session

    from rucio.common.types import InternalScope


class CustomDidMetaPlugin(DidMetaPlugin):
    """
    Interface for plugins managing metadata of DIDs
    """

    def __init__(self):
        super(CustomDidMetaPlugin, self).__init__()
        self.plugin_name = "LUCA"
    
    def get_metadata(self, scope: "InternalScope", name: str, *, session: "Optional[Session]" = None) -> "Any":
        """
        Get data identifier metadata

        :param scope: The scope name.
        :param name: The data identifier name.
        :param session: The database session in use.
        """
        print("Ecco a te i metadata!")

    def set_metadata(self, scope: "InternalScope", name: str, key: str, value: str, recursive: bool = False, *, session: "Optional[Session]" = None) -> None: #key: str, value: str,
        """
        Add metadata to data identifier.

        :param scope: The scope name.
        :param name: The data identifier name.
        :param key: the key.
        :param value: the value.
        :param did: The data identifier info.
        :param recursive: Option to propagate the metadata change to content.
        :param session: The database session in use.
        """
        if key == "JSON":
            try:
                dict = json.loads(value)
                print(type(dict))
            #try:
            #    lines = value.strip("{}\n ").replace("\t", "").splitlines()
            
            #    processed_lines = []
            #    for line in lines:
            #        if line.strip():  # Ignore empty lines
            #            keys, values = line.strip().split(":")
            #            # Add quotes around the value if not already quoted
            #            values = values.strip()
            #        if not (values.startswith('"') and values.endswith('"')):
            #            values = f'"{values}"'
            #            processed_lines.append(f'{keys.strip()}:{values}')

            #    processed_string = "{" + ", ".join(processed_lines) + "}"

            #    data = json.loads(processed_string)

            #    json_data = json.dumps(data, indent=4)

            #    print(json_data)
            #try:
            #    data = json.loads(value)
            #    for keys, values in value.items():
            #        print(json.dumps({keys: values}, indent=4))
            #    print("Ho settato i metadati")
            #try:
            #    with open(value, 'r') as json_file:
            #        data = json.load(json_file)
            #        for keys, values in data.items():
            #            print(json.dumps({keys: values}, indent=4))
            #        print("Ho settato i metadati")
            except Exception as e:
                print(f"Error reading JSON file: {e}")
        else:
            print("Key must be 'JSON'")

    def set_metadata_json(self, scope: "InternalScope", name: str, data: dict, key: str, value: str, recursive: bool = False, *, session: "Optional[Session]" = None) -> None:
        """
        Add metadata to data identifier.

        :param scope: The scope name.
        :param name: The data identifier name.
        :param file: Python dict converted from the original JSON file
        :param key: the key.
        :param value: the value.
        :param did: The data identifier info.
        :param recursive: Option to propagate the metadata change to content.
        :param session: The database session in use.
        """
        for key, value in data.items():
            print(json.dumps({key: value}, indent=4))
        print("Ho settato i metadati")


    def set_metadata_bulk(self, scope: "InternalScope", name: str, meta: dict[str, "Any"], recursive: bool = False, *, session: "Optional[Session]" = None) -> None:
        """
        Add metadata to data identifier in bulk.

        :param scope: The scope name.
        :param name: The data identifier name.
        :param meta: all key-values to set.
        :type meta: dict
        :param recursive: Option to propagate the metadata change to content.
        :param session: The database session in use.
        """
        for key, value in meta.items():
            self.set_metadata(scope, name, key, value, recursive=recursive, session=session)

    def delete_metadata(self, scope: "InternalScope", name: str, key: str, *, session: "Optional[Session]" = None) -> None:
        """
        Deletes the metadata stored for the given key.

        :param scope: The scope of the did.
        :param name: The name of the did.
        :param key: Key of the metadata.
        :param session: The database session in use.
        """
        print("Ho eliminato i metadati")

    def list_dids(
        self,
        scope: "InternalScope",
        filters: dict[str, "Any"],
        did_type: Literal['all', 'collection', 'dataset', 'container', 'file'] = 'collection',
        ignore_case: bool = False,
        limit: "Optional[int]" = None,
        offset: "Optional[int]" = None,
        long: bool = False,
        recursive: bool = False,
        *,
        session: "Optional[Session]" = None
    ) -> str: #"Iterator[Union[str, dict[str, Any]]]"
        """
        Search data identifiers

        :param scope: the scope name.
        :param filters: dictionary of attributes by which the results should be filtered.
        :param did_type: the type of the did: all(container, dataset, file), collection(dataset or container), dataset, container, file.
        :param ignore_case: ignore case distinctions.
        :param limit: limit number.
        :param offset: offset number.
        :param long: Long format option to display more information for each DID.
        :param session: The database session in use.
        :param recursive: Recursively list DIDs content.
        """
        print("Ecco la tua lista di dids")

    
    def manages_key(self, key: str, *, session: "Optional[Session]" = None) -> bool:
        """
        Returns whether key is managed by this plugin or not.
        :param key: Key of the metadata.
        :param session: The database session in use.
        :returns (Boolean)
        """
        return json_implemented(session=session)

    def get_plugin_name(self):
        """
        Returns a unique identifier for this plugin. This can be later used for filtering down results to this plugin only.
        :returns: The name of the plugin.
        """
        return self.plugin_name