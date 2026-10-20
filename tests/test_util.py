from datetime import timezone

import pytest

from agent_off_switch.util import InputError, as_of, cell, items, mask, parse_dt, tag_owner


def test_parse_dt_handles_z_offset_date_and_epoch():
    assert parse_dt("2026-01-02T03:04:05Z").tzinfo == timezone.utc
    assert parse_dt("2026-01-02T05:04:05+02:00").hour == 3
    assert parse_dt("2026-01-02").day == 2
    assert parse_dt(1767225600000).year == 2026
    assert parse_dt("2026-01-02T03:04:05.1234567Z").microsecond == 123456


def test_parse_dt_returns_none_for_empty_and_markers():
    for value in (None, "", "N/A", "no_information", "never", "garbage"):
        assert parse_dt(value) is None


def test_items_reads_graph_pages_lists_and_named_keys():
    assert items({"value": [{"a": 1}]}) == [{"a": 1}]
    assert items([[{"a": 1}], [{"a": 2}]]) == [{"a": 1}, {"a": 2}]
    assert items([{"value": [{"a": 1}]}, {"value": [{"a": 2}]}]) == [{"a": 1}, {"a": 2}]
    assert items({"installations": [{"id": 1}]}, "installations") == [{"id": 1}]
    assert items("text") == []


def test_mask_keeps_last_four_only():
    assert mask("AKIAIOSFODNN7EXAMPLE") == "****MPLE"
    assert mask("") == "****"


def test_as_of_is_end_of_day_and_rejects_bad_dates():
    assert as_of("2026-10-09").hour == 23
    with pytest.raises(InputError):
        as_of("09/10/2026")


def test_cell_escapes_pipes_and_newlines():
    assert cell("a|b\nc") == "a\\|b c"
    assert cell(None) == "-"


def test_tag_owner_reads_aws_and_entra_tags():
    assert tag_owner([{"Key": "Owner", "Value": "team@example.com"}]) == "team@example.com"
    assert tag_owner(["owner:team@example.com"]) == "team@example.com"
    assert tag_owner(["other"]) == ""


def test_parse_dt_out_of_range_is_no_date():
    for value in (10**20, -(10**20), 1e308, float("nan"), float("inf"), "9999-12-31T23:59:59-01:00"):
        assert parse_dt(value) is None


def test_cell_removes_carriage_returns():
    assert cell("a\r\nb\rc|d") == "a b c\\|d"
