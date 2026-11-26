"""A9: PDF text escaping and table-cell rendering."""

from app.reporting import templates


def test_safe_text_escapes_quotes():
    assert templates.safe_text("say \"hi\" it's") == "say &quot;hi&quot; it&#39;s"


def test_safe_text_strips_xml_illegal_control_characters():
    assert templates.safe_text("a\x00b\x07c\x1fd") == "abcd"


def test_safe_text_keeps_tab_and_newlines():
    assert templates.safe_text("a\tb\nc\rd") == "a\tb\nc\rd"


def test_safe_text_does_not_truncate():
    assert len(templates.safe_text("A" * 5000)) == 5000


def test_safe_text_does_not_double_escape():
    assert templates.safe_text("&amp;") == "&amp;amp;"


def test_table_cell_renders_escaped_text_as_the_original_characters():
    styles = templates.get_styles()
    cell = templates.table_cell('web & "db" <host>', styles)
    assert cell.getPlainText() == 'web & "db" <host>'


def test_table_cell_handles_missing_value():
    styles = templates.get_styles()
    assert templates.table_cell(None, styles).getPlainText() == ""
