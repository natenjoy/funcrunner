package scraper

func getPrompt(hostname, os string) string {
	switch os {
	case "eos", "ftos", "ios", "junos":
		return string("\n.*"+hostname[:12]) + ".+[#>]"
	case "sdx":
		return "\n>"
	case "vpx":
		return "\njoyroot>"
	case "sentry":
		return "\nSwitched PDU:"
	case "apc":
		return "\napc>"
	case "opengear":
		return "\n\\$"
	}
	return "\n.+[#,>]"
}
