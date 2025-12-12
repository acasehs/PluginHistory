"""
Custom Filter Lists Management
Allows users to create, save, and load custom filter lists.
"""

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Any, Set


@dataclass
class FilterList:
    """A named list of filter items (hostnames, plugins, etc.)."""

    name: str
    description: str = ''
    filter_type: str = 'hostname'  # hostname, plugin_id, ip_address, location, tier, etc.
    items: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    modified_at: datetime = field(default_factory=datetime.now)
    tags: List[str] = field(default_factory=list)

    def add_item(self, item: str) -> None:
        """Add an item to the list."""
        if item not in self.items:
            self.items.append(item)
            self.modified_at = datetime.now()

    def add_items(self, items: List[str]) -> None:
        """Add multiple items to the list."""
        for item in items:
            if item not in self.items:
                self.items.append(item)
        self.modified_at = datetime.now()

    def remove_item(self, item: str) -> bool:
        """Remove an item from the list."""
        if item in self.items:
            self.items.remove(item)
            self.modified_at = datetime.now()
            return True
        return False

    def clear(self) -> None:
        """Clear all items from the list."""
        self.items = []
        self.modified_at = datetime.now()

    def contains(self, item: str) -> bool:
        """Check if an item is in the list (case-insensitive)."""
        return item.lower() in [i.lower() for i in self.items]

    @property
    def count(self) -> int:
        """Get number of items in the list."""
        return len(self.items)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'name': self.name,
            'description': self.description,
            'filter_type': self.filter_type,
            'items': self.items,
            'created_at': self.created_at.isoformat(),
            'modified_at': self.modified_at.isoformat(),
            'tags': self.tags
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FilterList':
        """Create from dictionary."""
        return cls(
            name=data['name'],
            description=data.get('description', ''),
            filter_type=data.get('filter_type', 'hostname'),
            items=data.get('items', []),
            created_at=datetime.fromisoformat(data['created_at']) if 'created_at' in data else datetime.now(),
            modified_at=datetime.fromisoformat(data['modified_at']) if 'modified_at' in data else datetime.now(),
            tags=data.get('tags', [])
        )


class FilterListManager:
    """Manages multiple filter lists with persistence."""

    def __init__(self, storage_dir: str = None):
        """
        Initialize the filter list manager.

        Args:
            storage_dir: Directory for storing filter lists. Defaults to ~/.nessus_tracker/filters/
        """
        if storage_dir is None:
            storage_dir = os.path.join(os.path.expanduser('~'), '.nessus_tracker', 'filters')

        self.storage_dir = storage_dir
        self._lists: Dict[str, FilterList] = {}

        # Create storage directory if it doesn't exist
        os.makedirs(self.storage_dir, exist_ok=True)

        # Load existing lists
        self._load_all_lists()

    def _load_all_lists(self) -> None:
        """Load all filter lists from storage directory."""
        for filename in os.listdir(self.storage_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(self.storage_dir, filename)
                try:
                    filter_list = load_filter_list(filepath)
                    if filter_list:
                        self._lists[filter_list.name] = filter_list
                except Exception as e:
                    print(f"Error loading filter list {filename}: {e}")

    def get_list(self, name: str) -> Optional[FilterList]:
        """Get a filter list by name."""
        return self._lists.get(name)

    def get_all_lists(self) -> List[FilterList]:
        """Get all filter lists."""
        return list(self._lists.values())

    def get_lists_by_type(self, filter_type: str) -> List[FilterList]:
        """Get all filter lists of a specific type."""
        return [fl for fl in self._lists.values() if fl.filter_type == filter_type]

    def get_lists_by_tag(self, tag: str) -> List[FilterList]:
        """Get all filter lists with a specific tag."""
        return [fl for fl in self._lists.values() if tag in fl.tags]

    def create_list(self, name: str, filter_type: str = 'hostname',
                   description: str = '', items: List[str] = None,
                   tags: List[str] = None) -> FilterList:
        """
        Create a new filter list.

        Args:
            name: Unique name for the list
            filter_type: Type of items in the list
            description: Description of the list
            items: Initial items
            tags: Tags for categorization

        Returns:
            Created FilterList
        """
        filter_list = FilterList(
            name=name,
            description=description,
            filter_type=filter_type,
            items=items or [],
            tags=tags or []
        )

        self._lists[name] = filter_list
        self.save_list(name)

        return filter_list

    def delete_list(self, name: str) -> bool:
        """Delete a filter list."""
        if name in self._lists:
            del self._lists[name]

            # Remove from storage
            filepath = os.path.join(self.storage_dir, f"{self._sanitize_filename(name)}.json")
            if os.path.exists(filepath):
                os.remove(filepath)

            return True
        return False

    def save_list(self, name: str) -> bool:
        """Save a filter list to storage."""
        if name not in self._lists:
            return False

        filter_list = self._lists[name]
        filepath = os.path.join(self.storage_dir, f"{self._sanitize_filename(name)}.json")

        return save_filter_list(filter_list, filepath)

    def save_all_lists(self) -> None:
        """Save all filter lists to storage."""
        for name in self._lists:
            self.save_list(name)

    def import_from_file(self, filepath: str) -> Optional[FilterList]:
        """Import a filter list from a file."""
        filter_list = load_filter_list(filepath)
        if filter_list:
            self._lists[filter_list.name] = filter_list
            self.save_list(filter_list.name)
        return filter_list

    def export_to_file(self, name: str, filepath: str) -> bool:
        """Export a filter list to a specific file."""
        if name not in self._lists:
            return False
        return save_filter_list(self._lists[name], filepath)

    def _sanitize_filename(self, name: str) -> str:
        """Sanitize a name for use as filename."""
        return "".join(c if c.isalnum() or c in '._-' else '_' for c in name)

    def get_list_names(self) -> List[str]:
        """Get all list names."""
        return list(self._lists.keys())

    def list_exists(self, name: str) -> bool:
        """Check if a list exists."""
        return name in self._lists


def save_filter_list(filter_list: FilterList, filepath: str) -> bool:
    """
    Save a filter list to a JSON file.

    Args:
        filter_list: FilterList to save
        filepath: Path to save to

    Returns:
        True if successful
    """
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(filter_list.to_dict(), f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving filter list: {e}")
        return False


def load_filter_list(filepath: str) -> Optional[FilterList]:
    """
    Load a filter list from a JSON file.

    Args:
        filepath: Path to load from

    Returns:
        FilterList or None if error
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return FilterList.from_dict(data)
    except Exception as e:
        print(f"Error loading filter list: {e}")
        return None


def create_filter_list_from_dataframe(df, column: str, name: str,
                                      filter_type: str = None) -> FilterList:
    """
    Create a filter list from unique values in a DataFrame column.

    Args:
        df: pandas DataFrame
        column: Column to extract unique values from
        name: Name for the filter list
        filter_type: Type of filter (defaults to column name)

    Returns:
        FilterList with unique values
    """
    import pandas as pd

    items = df[column].dropna().unique().tolist()
    items = [str(item) for item in items]

    return FilterList(
        name=name,
        filter_type=filter_type or column,
        items=items,
        description=f"Auto-generated from column '{column}'"
    )
