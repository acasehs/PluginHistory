"""
Filter Engine Module
Centralized filtering logic for all data types.
"""

import pandas as pd
import numpy as np
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Any, Set, Callable
from enum import Enum

from .hostname_parser import parse_hostname, HostType
from .custom_lists import FilterList


class FilterOperator(Enum):
    """Filter comparison operators."""
    EQUALS = 'equals'
    NOT_EQUALS = 'not_equals'
    CONTAINS = 'contains'
    NOT_CONTAINS = 'not_contains'
    STARTS_WITH = 'starts_with'
    ENDS_WITH = 'ends_with'
    IN_LIST = 'in_list'
    NOT_IN_LIST = 'not_in_list'
    GREATER_THAN = 'greater_than'
    LESS_THAN = 'less_than'
    GREATER_EQUAL = 'greater_equal'
    LESS_EQUAL = 'less_equal'
    BETWEEN = 'between'
    IS_NULL = 'is_null'
    NOT_NULL = 'not_null'


@dataclass
class FilterCriteria:
    """A single filter criterion."""

    column: str
    operator: FilterOperator
    value: Any = None
    value2: Any = None  # For BETWEEN operator
    case_sensitive: bool = False

    def apply(self, df: pd.DataFrame) -> pd.DataFrame:
        """Apply this filter to a DataFrame."""
        if self.column not in df.columns:
            return df

        series = df[self.column]

        # Handle case sensitivity for string columns
        if not self.case_sensitive and series.dtype == 'object':
            series = series.str.lower()
            if isinstance(self.value, str):
                value = self.value.lower()
            elif isinstance(self.value, list):
                value = [v.lower() if isinstance(v, str) else v for v in self.value]
            else:
                value = self.value
        else:
            value = self.value

        # Apply operator
        if self.operator == FilterOperator.EQUALS:
            mask = series == value
        elif self.operator == FilterOperator.NOT_EQUALS:
            mask = series != value
        elif self.operator == FilterOperator.CONTAINS:
            mask = series.astype(str).str.contains(str(value), case=self.case_sensitive, na=False)
        elif self.operator == FilterOperator.NOT_CONTAINS:
            mask = ~series.astype(str).str.contains(str(value), case=self.case_sensitive, na=False)
        elif self.operator == FilterOperator.STARTS_WITH:
            mask = series.astype(str).str.startswith(str(value), na=False)
        elif self.operator == FilterOperator.ENDS_WITH:
            mask = series.astype(str).str.endswith(str(value), na=False)
        elif self.operator == FilterOperator.IN_LIST:
            mask = series.isin(value if isinstance(value, list) else [value])
        elif self.operator == FilterOperator.NOT_IN_LIST:
            mask = ~series.isin(value if isinstance(value, list) else [value])
        elif self.operator == FilterOperator.GREATER_THAN:
            mask = pd.to_numeric(series, errors='coerce') > value
        elif self.operator == FilterOperator.LESS_THAN:
            mask = pd.to_numeric(series, errors='coerce') < value
        elif self.operator == FilterOperator.GREATER_EQUAL:
            mask = pd.to_numeric(series, errors='coerce') >= value
        elif self.operator == FilterOperator.LESS_EQUAL:
            mask = pd.to_numeric(series, errors='coerce') <= value
        elif self.operator == FilterOperator.BETWEEN:
            numeric = pd.to_numeric(series, errors='coerce')
            mask = (numeric >= value) & (numeric <= self.value2)
        elif self.operator == FilterOperator.IS_NULL:
            mask = series.isna() | (series == '')
        elif self.operator == FilterOperator.NOT_NULL:
            mask = series.notna() & (series != '')
        else:
            return df

        return df[mask]


class FilterEngine:
    """
    Centralized filter engine for all data filtering operations.

    Supports:
    - Hostname filtering (by pattern, type, location, tier, environment)
    - Severity filtering
    - Date range filtering
    - CVSS score range filtering
    - Status filtering (Active/Resolved)
    - OPDIR compliance filtering
    - Custom filter lists
    """

    def __init__(self):
        self.criteria: List[FilterCriteria] = []
        self.custom_filters: Dict[str, Callable] = {}

    def clear(self) -> None:
        """Clear all filter criteria."""
        self.criteria = []

    def add_criterion(self, criterion: FilterCriteria) -> 'FilterEngine':
        """Add a filter criterion."""
        self.criteria.append(criterion)
        return self

    def add_custom_filter(self, name: str, filter_func: Callable[[pd.DataFrame], pd.DataFrame]) -> 'FilterEngine':
        """Add a custom filter function."""
        self.custom_filters[name] = filter_func
        return self

    def apply(self, df: pd.DataFrame) -> pd.DataFrame:
        """Apply all filters to a DataFrame."""
        result = df.copy()

        # Apply criteria
        for criterion in self.criteria:
            result = criterion.apply(result)

        # Apply custom filters
        for filter_func in self.custom_filters.values():
            result = filter_func(result)

        return result

    # Convenience methods for common filters

    def filter_by_hostname(self, hostname_pattern: str, operator: FilterOperator = FilterOperator.CONTAINS) -> 'FilterEngine':
        """Add hostname filter."""
        return self.add_criterion(FilterCriteria(
            column='hostname',
            operator=operator,
            value=hostname_pattern
        ))

    def filter_by_hostname_list(self, hostnames: List[str], include: bool = True) -> 'FilterEngine':
        """Filter by list of hostnames."""
        return self.add_criterion(FilterCriteria(
            column='hostname',
            operator=FilterOperator.IN_LIST if include else FilterOperator.NOT_IN_LIST,
            value=hostnames
        ))

    def filter_by_host_type(self, host_type: HostType) -> 'FilterEngine':
        """Filter by host type (physical/virtual/ilom)."""
        def type_filter(df: pd.DataFrame) -> pd.DataFrame:
            if 'hostname' not in df.columns:
                return df

            def matches_type(hostname):
                parsed = parse_hostname(hostname)
                return parsed.host_type == host_type

            mask = df['hostname'].apply(matches_type)
            return df[mask]

        return self.add_custom_filter(f'host_type_{host_type.value}', type_filter)

    def filter_by_location(self, location: str) -> 'FilterEngine':
        """Filter by hostname location code."""
        def location_filter(df: pd.DataFrame) -> pd.DataFrame:
            if 'hostname' not in df.columns:
                return df

            def matches_location(hostname):
                parsed = parse_hostname(hostname)
                return parsed.location.lower() == location.lower()

            mask = df['hostname'].apply(matches_location)
            return df[mask]

        return self.add_custom_filter(f'location_{location}', location_filter)

    def filter_by_tier(self, tier: str) -> 'FilterEngine':
        """Filter by hostname tier code."""
        def tier_filter(df: pd.DataFrame) -> pd.DataFrame:
            if 'hostname' not in df.columns:
                return df

            def matches_tier(hostname):
                parsed = parse_hostname(hostname)
                return parsed.tier.lower() == tier.lower()

            mask = df['hostname'].apply(matches_tier)
            return df[mask]

        return self.add_custom_filter(f'tier_{tier}', tier_filter)

    def filter_by_environment(self, environment: str) -> 'FilterEngine':
        """Filter by hostname environment code."""
        def env_filter(df: pd.DataFrame) -> pd.DataFrame:
            if 'hostname' not in df.columns:
                return df

            def matches_env(hostname):
                parsed = parse_hostname(hostname)
                return parsed.environment.lower() == environment.lower()

            mask = df['hostname'].apply(matches_env)
            return df[mask]

        return self.add_custom_filter(f'environment_{environment}', env_filter)

    def filter_by_severity(self, severities: List[str]) -> 'FilterEngine':
        """Filter by severity level(s)."""
        return self.add_criterion(FilterCriteria(
            column='severity_text',
            operator=FilterOperator.IN_LIST,
            value=severities
        ))

    def filter_exclude_info(self) -> 'FilterEngine':
        """Exclude informational findings."""
        return self.add_criterion(FilterCriteria(
            column='severity_text',
            operator=FilterOperator.NOT_EQUALS,
            value='Info'
        ))

    def filter_by_status(self, status: str) -> 'FilterEngine':
        """Filter by status (Active/Resolved)."""
        return self.add_criterion(FilterCriteria(
            column='status',
            operator=FilterOperator.EQUALS,
            value=status
        ))

    def filter_by_date_range(self, start_date: datetime, end_date: datetime,
                             date_column: str = 'scan_date') -> 'FilterEngine':
        """Filter by date range."""
        def date_filter(df: pd.DataFrame) -> pd.DataFrame:
            if date_column not in df.columns:
                return df

            dates = pd.to_datetime(df[date_column], errors='coerce')
            mask = (dates >= start_date) & (dates <= end_date)
            return df[mask]

        return self.add_custom_filter(f'date_range_{date_column}', date_filter)

    def filter_by_scan_date(self, scan_dates: List[datetime]) -> 'FilterEngine':
        """Filter to specific scan dates."""
        def scan_filter(df: pd.DataFrame) -> pd.DataFrame:
            if 'scan_date' not in df.columns:
                return df

            dates = pd.to_datetime(df['scan_date'], errors='coerce')
            mask = dates.isin(scan_dates)
            return df[mask]

        return self.add_custom_filter('scan_dates', scan_filter)

    def filter_by_cvss_range(self, min_score: float = 0.0, max_score: float = 10.0,
                             cvss_column: str = 'cvss3_base_score') -> 'FilterEngine':
        """Filter by CVSS score range."""
        def cvss_filter(df: pd.DataFrame) -> pd.DataFrame:
            if cvss_column not in df.columns:
                return df

            scores = pd.to_numeric(df[cvss_column], errors='coerce')
            mask = (scores >= min_score) & (scores <= max_score)
            return df[mask]

        return self.add_custom_filter(f'cvss_range_{cvss_column}', cvss_filter)

    def filter_by_opdir_status(self, status: str) -> 'FilterEngine':
        """Filter by OPDIR compliance status."""
        return self.add_criterion(FilterCriteria(
            column='opdir_status',
            operator=FilterOperator.EQUALS,
            value=status
        ))

    def filter_has_opdir(self, has_opdir: bool = True) -> 'FilterEngine':
        """Filter to findings with or without OPDIR mapping."""
        return self.add_criterion(FilterCriteria(
            column='opdir_number',
            operator=FilterOperator.NOT_NULL if has_opdir else FilterOperator.IS_NULL
        ))

    def filter_by_filter_list(self, filter_list: FilterList, include: bool = True) -> 'FilterEngine':
        """Apply a custom filter list."""
        column_mapping = {
            'hostname': 'hostname',
            'plugin_id': 'plugin_id',
            'ip_address': 'ip_address',
            'location': None,  # Uses custom logic
            'tier': None,
            'environment': None,
        }

        column = column_mapping.get(filter_list.filter_type, filter_list.filter_type)

        if column:
            return self.add_criterion(FilterCriteria(
                column=column,
                operator=FilterOperator.IN_LIST if include else FilterOperator.NOT_IN_LIST,
                value=filter_list.items
            ))
        elif filter_list.filter_type == 'location':
            for location in filter_list.items:
                self.filter_by_location(location)
        elif filter_list.filter_type == 'tier':
            for tier in filter_list.items:
                self.filter_by_tier(tier)

        return self


def apply_filters(df: pd.DataFrame,
                  hostname: str = None,
                  hostname_list: List[str] = None,
                  host_type: str = None,
                  location: str = None,
                  tier: str = None,
                  environment: str = None,
                  severity: List[str] = None,
                  include_info: bool = True,
                  status: str = None,
                  start_date: datetime = None,
                  end_date: datetime = None,
                  cvss_min: float = None,
                  cvss_max: float = None,
                  opdir_status: str = None,
                  has_opdir: bool = None) -> pd.DataFrame:
    """
    Apply multiple filters to a DataFrame using a convenient function interface.

    Args:
        df: DataFrame to filter
        hostname: Hostname pattern to match
        hostname_list: List of hostnames to include
        host_type: Host type filter ('physical', 'virtual', 'ilom')
        location: Location code filter
        tier: Tier code filter
        environment: Environment code filter
        severity: List of severities to include
        include_info: Whether to include Info severity
        status: Status filter ('Active', 'Resolved')
        start_date: Start of date range
        end_date: End of date range
        cvss_min: Minimum CVSS score
        cvss_max: Maximum CVSS score
        opdir_status: OPDIR status filter
        has_opdir: Filter by OPDIR presence

    Returns:
        Filtered DataFrame
    """
    engine = FilterEngine()

    if hostname:
        engine.filter_by_hostname(hostname)

    if hostname_list:
        engine.filter_by_hostname_list(hostname_list)

    if host_type:
        type_mapping = {
            'physical': HostType.PHYSICAL,
            'virtual': HostType.VIRTUAL,
            'ilom': HostType.ILOM
        }
        if host_type.lower() in type_mapping:
            engine.filter_by_host_type(type_mapping[host_type.lower()])

    if location:
        engine.filter_by_location(location)

    if tier:
        engine.filter_by_tier(tier)

    if environment:
        engine.filter_by_environment(environment)

    if severity:
        engine.filter_by_severity(severity)

    if not include_info:
        engine.filter_exclude_info()

    if status:
        engine.filter_by_status(status)

    if start_date and end_date:
        engine.filter_by_date_range(start_date, end_date)

    if cvss_min is not None or cvss_max is not None:
        engine.filter_by_cvss_range(
            min_score=cvss_min or 0.0,
            max_score=cvss_max or 10.0
        )

    if opdir_status:
        engine.filter_by_opdir_status(opdir_status)

    if has_opdir is not None:
        engine.filter_has_opdir(has_opdir)

    return engine.apply(df)
