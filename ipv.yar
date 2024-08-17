rule mspy : ipvrat
{
  meta:
    description = "detection for tool sometimes utilized for IPV"
    threat_level = 3
    in_the_wild = true

  strings:
    $s1 = "debug.mspyonline.com"
    $s2 = "a.thd.cc"
    $s3 = "bugsense.appsport.com"

  condition:
    all of them
}

rule flexispy : ipvrat
{
  meta:
    description = "detection for tool sometimes utilized for IPV"
    threat_level = 3
    in_the_wild = true

  strings:
    $s1 = "Your product is disabled. Contact support, quoting your Activation Code"
    $s2 = "Using real phone information"
    $s3 =  "Spy Call"

  condition:
    all of them
}
