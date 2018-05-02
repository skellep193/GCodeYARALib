rule Exceeds_Max_Z
{
	meta:
		author = "skellep193"
		description = "Looks for g-code exceeding max-z"
		date = "2018-05"
	strings:
		$c0 = /[0-9a-fA-F]{20}/ fullword ascii
	condition:
		$c0
}