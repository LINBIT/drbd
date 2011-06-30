<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

  <xsl:template match="/">
    <cmdsynopsis sepchar=" ">
      <command moreinfo="none">drbdsetup</command>
      <xsl:apply-templates select="command"/>
    </cmdsynopsis>
  </xsl:template>

  <xsl:template match="command">
    <arg choice="plain" rep="norepeat">
      <xsl:value-of select="@name"/>
    </arg>
    <xsl:apply-templates select="argument|group"/>
    <xsl:apply-templates select="option"/>
  </xsl:template>

  <xsl:template match="group">
    <group>
      <xsl:apply-templates/>
    </group>
  </xsl:template>

  <xsl:template match="argument">
    <arg choice="req" rep="norepeat">
      <replaceable><xsl:value-of select="."/></replaceable>
    </arg>
  </xsl:template>

  <xsl:template match="option[@type = 'numeric'] | option[@type='string']">
    <arg choice="opt" rep="norepeat">
      <xsl:text>--</xsl:text>
      <xsl:value-of select="@name"/>
      <xsl:text> </xsl:text>
      <arg choice="req" rep="norepeat"><replaceable>val</replaceable></arg>
    </arg>
  </xsl:template>

  <xsl:template match="option[@type = 'handler']">
    <arg choice="opt" rep="norepeat">--<xsl:value-of select="@name"/>
      <group choice="req" rep="norepeat">
	<xsl:apply-templates select="handler"/>
      </group>
    </arg>
  </xsl:template>

  <xsl:template match="option[@type = 'boolean']">
    <arg choice="opt" rep="norepeat">--<xsl:value-of select="@name"/></arg>
  </xsl:template>

  <xsl:template match="handler">
    <arg choice="plain" rep="norepeat">
      <xsl:value-of select="."/>
    </arg>
  </xsl:template>

</xsl:stylesheet>
