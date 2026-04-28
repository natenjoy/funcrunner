package scraper

func getPreamble(os string) []string {
	switch os {
	case "eos", "ios":
		return []string{"terminal length 0", "terminal width 300"}
	case "ftos":
		return []string{"terminal length 0"}
	case "junos":
		return []string{"set cli screen-length 0", "set cli screen-width 300"}
	}
	return []string{}
}
