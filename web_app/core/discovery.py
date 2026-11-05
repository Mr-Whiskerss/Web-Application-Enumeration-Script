"""
Discovered State Module

Shared discovered state for URLs, parameters, and endpoints discovered during scanning.
"""

from .state import DiscoveredState

# Singleton instance shared across all phases
DISCOVERED = DiscoveredState()

__all__ = ["DISCOVERED", "DiscoveredState"]
