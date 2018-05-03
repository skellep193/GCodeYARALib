rule Exceeds_Max_Extruder_Temp
{
	meta:
		author = "skellep193"
		description = "Looks for g-code exceeding max extruder temp"
		date = "2018-05"
	strings:
		$re1 = /M104 S[0-9]+/

	condition:
		$re1
}