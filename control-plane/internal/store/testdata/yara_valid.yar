import "pe"

/* block { comment with "quotes" */
private rule IsPE : exe tag2 {
  meta:
    author = "x { y"
    score = 70
  strings:
    $mz = { 4D 5A [2-4] ?? }
    $re = /https?:\/\/[a-z]{3,}\.example\/\{x/ nocase
    $t = "}" wide ascii
    $esc = "say \"hi\" }"
  condition:
    $mz at 0 and ($re or $t or $esc) and filesize < 2MB and filesize \ 2 > 10
}

global rule Global_NonEmpty { condition: filesize > 0 }

rule Section_Name_Matches // trailing comment {
{
  condition:
    IsPE and pe.number_of_sections > 0 and pe.sections[0].name matches /\.te{1}xt/
}

rule Multi_Line_Condition
{
    strings:
        $a = "rule fake { condition: }"
        $b = { E8 ( 00 | 01 ) ?? ?? ?? }
    condition:
        for any i in (1..#a) : ( @a[i] < 100 ) or
        $b
}
