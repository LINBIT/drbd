<?xml version="1.0" encoding="UTF-8"?>
<!-- Handcrafted by phil@linbit.com -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:template match="/">
  <cmdsynopsis sepchar=" ">
    <command moreinfo="none">drbdsetup</command>
    <arg choice="req" rep="norepeat"><replaceable><xsl:value-of select="command/@operates_on"/></replaceable></arg>
    <arg choice="plain" rep="norepeat"><xsl:value-of select="command/@name"/></arg>

    <xsl:for-each select="/command/argument">
      <arg choice="req" rep="norepeat">
	<replaceable><xsl:value-of select="."/></replaceable>
      </arg>
    </xsl:for-each>

    <xsl:for-each select="/command/option">

      <arg choice="opt" rep="norepeat">--<xsl:value-of select="@name"/>

	  <xsl:if test="@type = 'numeric' or @type = 'string'">
	    <arg choice="req" rep="norepeat"><replaceable>val</replaceable></arg>
	  </xsl:if>

	  <xsl:if test="@type = 'handler'">
	    <arg choice="req" rep="norepeat"><group choice="opt" rep="norepeat">
	      <xsl:for-each select="handler">
		<arg choice="plain" rep="norepeat">
		  <xsl:value-of select="."/>
		</arg>
	      </xsl:for-each>
	    </group></arg>
	  </xsl:if>

	  <!-- @type = 'boolean' gets ignored -->
      </arg>

    </xsl:for-each>

  </cmdsynopsis>
</xsl:template>

</xsl:stylesheet>
