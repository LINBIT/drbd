<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

  <xsl:template match="/">
    <term>
      <command moreinfo="none">drbdsetup</command>
      <xsl:apply-templates select="command"/>
    </term>
  </xsl:template>

  <xsl:template match="command">
    <arg choice="plain" rep="norepeat">
      <xsl:value-of select="@name"/>
    </arg>
    <xsl:apply-templates select="argument|group"/>
    <xsl:apply-templates select="option"/>
  </xsl:template>

  <xsl:template match="group">
    <group choice="req">
      <xsl:apply-templates/>
    </group>
  </xsl:template>

  <xsl:template match="argument">
    <arg choice="plain" rep="norepeat">
      <replaceable><xsl:value-of select="."/></replaceable>
    </arg>
  </xsl:template>

  <xsl:template match="option">
  </xsl:template>

  <xsl:template match="handler">
    <arg choice="plain" rep="norepeat">
      <xsl:value-of select="."/>
    </arg>
  </xsl:template>

</xsl:stylesheet>
