import unittest

from .parsers import WhoisParser, extract_known_fields, parse_generic


class ParseGenericTests(unittest.TestCase):
    def test_parses_key_value_lines(self):
        raw = "inetnum: 1.2.3.0 - 1.2.3.255\nnetname: TEST-NET\n"
        parsed = parse_generic(raw)
        self.assertEqual(parsed["inetnum"], ["1.2.3.0 - 1.2.3.255"])
        self.assertEqual(parsed["netname"], ["TEST-NET"])

    def test_repeated_keys_become_a_list(self):
        raw = "descr: line one\ndescr: line two\n"
        parsed = parse_generic(raw)
        self.assertEqual(parsed["descr"], ["line one", "line two"])

    def test_normalizes_key_casing_and_separators(self):
        raw = "OrgAbuseEmail:  abuse@example.com\nabuse-mailbox: abuse2@example.com\n"
        parsed = parse_generic(raw)
        self.assertIn("orgabuseemail", parsed)
        self.assertIn("abuse_mailbox", parsed)

    def test_skips_comments_and_blank_lines(self):
        raw = "% comment\n# also a comment\n\ncountry: US\n"
        parsed = parse_generic(raw)
        self.assertEqual(parsed, {"country": ["US"]})

    def test_skips_lines_without_colon(self):
        raw = "this is not a field\ncountry: US\n"
        parsed = parse_generic(raw)
        self.assertEqual(parsed, {"country": ["US"]})

    def test_skips_key_with_empty_value(self):
        raw = "remarks:\ncountry: US\n"
        parsed = parse_generic(raw)
        self.assertNotIn("remarks", parsed)

    def test_empty_input(self):
        self.assertEqual(parse_generic(""), {})


class ExtractKnownFieldsTests(unittest.TestCase):
    def test_ripe_style_fields(self):
        parsed = parse_generic(
            "inetnum: 5.1.0.0 - 5.1.3.255\n"
            "netname: IR-TIC\n"
            "country: IR\n"
            "org: ORG-TIC1-RIPE\n"
            "origin: AS12880\n"
            "route: 5.1.0.0/22\n"
            "mnt-by: IR-TIC-MNT\n"
            "abuse-mailbox: abuse@tic.ir\n"
        )
        known = extract_known_fields(parsed)
        self.assertEqual(
            known,
            {
                "inetnum": "5.1.0.0 - 5.1.3.255",
                "netname": "IR-TIC",
                "country": "IR",
                "organization": "ORG-TIC1-RIPE",
                "origin": "AS12880",
                "route": "5.1.0.0/22",
                "mnt_by": "IR-TIC-MNT",
                "abuse_email": "abuse@tic.ir",
            },
        )

    def test_arin_style_fields(self):
        parsed = parse_generic(
            "NetRange: 1.2.3.0 - 1.2.3.255\nOrgName: Acme Corp\n"
            "Country: US\nOrgAbuseEmail: abuse@acme.example\n"
        )
        known = extract_known_fields(parsed)
        self.assertEqual(known["inetnum"], "1.2.3.0 - 1.2.3.255")
        self.assertEqual(known["organization"], "Acme Corp")
        self.assertEqual(known["abuse_email"], "abuse@acme.example")

    def test_missing_fields_are_simply_absent(self):
        parsed = parse_generic("country: US\n")
        known = extract_known_fields(parsed)
        self.assertEqual(known, {"country": "US"})
        self.assertNotIn("organization", known)
        self.assertNotIn("asn", known)

    def test_empty_parse_returns_empty_dict(self):
        self.assertEqual(extract_known_fields({}), {})

    def test_first_alias_match_wins(self):
        # "owner" (Brazilian registry style) should be picked when
        # "orgname"/"organization" aren't present.
        parsed = parse_generic("owner: Some Org\n")
        known = extract_known_fields(parsed)
        self.assertEqual(known["organization"], "Some Org")


class WhoisParserTests(unittest.TestCase):
    def test_parse_returns_both_generic_and_known(self):
        raw = "inetnum: 1.2.3.0 - 1.2.3.255\nnetname: TEST-NET\ncountry: US\n"
        generic, known = WhoisParser().parse(raw)
        self.assertEqual(generic["netname"], ["TEST-NET"])
        self.assertEqual(known["netname"], "TEST-NET")
