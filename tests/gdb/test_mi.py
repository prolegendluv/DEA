import pytest

from dea.adapters.gdb.mi import MIList, MIMap, MIParseError, MIParser, parse_record


@pytest.mark.parametrize("line,kind,cls,token", [
    ('1^done', '^', 'done', 1), ('2^running', '^', 'running', 2),
    ('^done', '^', 'done', None), ('*stopped,reason="breakpoint-hit"', '*', 'stopped', None),
    ('7*running,thread-id="all"', '*', 'running', 7),
    ('=thread-created,id="2",group-id="i1"', '=', 'thread-created', None),
    ('+download,section=".text"', '+', 'download', None),
    ('3^error,msg="Cannot access memory"', '^', 'error', 3),
    ('9^exit', '^', 'exit', 9), ('~"console\\n"', '~', '', None),
    ('@"target\\n"', '@', '', None), ('&"diagnostics\\n"', '&', '', None),
    ('9223372036854775807^done', '^', 'done', 2**63 - 1),
    ('*stopped,reason="watchpoint-trigger",wpt={number="2",exp="count"},value={old="1",new="2"}', '*', 'stopped', None),
    ('*stopped,reason="signal-received",signal-name="SIGSEGV",thread-id="5"', '*', 'stopped', None),
    ('=library-loaded,id="lib",ranges=[{from="0x1",to="0x2"}]', '=', 'library-loaded', None),
    ('^done,x=[],y={},z=""', '^', 'done', None),
])
def test_record_variants(line, kind, cls, token):
    record = parse_record(line)
    assert (record.kind, record.cls, record.token) == (kind, cls, token)


def test_nested_results_and_repeated_keys_are_lossless():
    record = parse_record('1^done,stack=[frame={level="0",args=[{name="x",value="1"}]},frame={level="1"}],x="a",x="b",values=["one",["two"],{}]')
    assert record.results.all("x") == ("a", "b")
    frames = record.results["stack"].values
    assert frames[0][0] == "frame" and frames[1][0] == "frame"
    assert frames[0][1]["args"].values[0]["value"] == "1"
    assert record.results["values"].values == ("one", MIList(("two",)), MIMap())


def test_c_string_escapes_and_utf8_octets():
    record = parse_record(r'^done,value="\a\b\t\n\v\f\r\"\047\\\?\101\x42\303\251"')
    assert record.results["value"] == '\a\b\t\n\v\f\r"\'\\?ABé'


def test_non_utf8_c_octets_preserved_without_replacement():
    value = parse_record(r'^done,value="\377"').results["value"]
    assert value.encode("utf-8", "surrogateescape") == b"\xff"


@pytest.mark.parametrize("line", [
    'garbage', '^', '1~"bad"', '^done,x=unquoted', '^done,x="unterminated',
    '^done,x="\\q"', '^done,x="\\x"', '^done,x="\\777"',
    '^done,x=["a",name="b"]', '^done,x=[name="a","b"]',
    '^done,x={name="a",}', '^done,', '^done,x="a" trailing',
    '9223372036854775808^done', '^done,x=[[[[[',
])
def test_malformed_records_fail_explicitly(line):
    with pytest.raises(MIParseError):
        parse_record(line)


def test_every_byte_fragment_boundary_and_multiple_records():
    data = '=thread-created,id="2"\r\n~"हिंदी é\\n"\n21^done,stack=[frame={level="0",func="f"}]\n(gdb) \n'.encode()
    expected = MIParser().feed(data)
    for split in range(len(data) + 1):
        parser = MIParser()
        assert parser.feed(data[:split]) + parser.feed(data[split:]) == expected
        assert parser.finish() == ()
    parser = MIParser()
    assert tuple(record for byte in data for record in parser.feed(bytes([byte]))) == expected


def test_eof_prompt_limits_and_excessive_recursion():
    parser = MIParser()
    assert parser.feed(b"(gdb) ") == ()
    assert parser.finish() == ()
    parser.feed(b'1^do')
    with pytest.raises(MIParseError, match="Truncated"):
        parser.finish()
    with pytest.raises(MIParseError, match="byte limit"):
        MIParser(5).feed(b'1^done\n')
    with pytest.raises(MIParseError):
        parse_record('^done,x=' + '[' * 70 + '"x"' + ']' * 70)


def test_stream_content_is_not_parsed_again():
    record = parse_record(r'@"*stopped,reason=\"signal-received\"\n1^done\n"')
    assert record.kind == "@"
    assert record.text.startswith("*stopped")
