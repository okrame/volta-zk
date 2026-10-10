import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import c71_profile_window as window


def test_only_complete_original_A_groups_trigger_capture():
    row = {'event': {'phase': 'pcs_a_resident', 'work': {'boundary': 'end', 'completed_groups': 33},
                     'geometry': {'groups': 512}}}
    assert window.completed_group(row) == 33
    row['event']['work']['boundary'] = 'start'
    assert window.completed_group(row) is None
    row['event']['work']['boundary'] = 'end'
    row['event']['phase'] = 'pcs_w_resident'
    assert window.completed_group(row) is None


def test_window_rejects_changed_geometry_and_invalid_group_counts():
    row = {'event': {'phase': 'pcs_a_resident', 'work': {'boundary': 'end', 'completed_groups': 33},
                     'geometry': {'groups': 511}}}
    with pytest.raises(ValueError):
        window.completed_group(row)
    row['event']['geometry']['groups'] = 512
    for count in (True, -1, 513):
        row['event']['work']['completed_groups'] = count
        with pytest.raises(ValueError):
            window.completed_group(row)
