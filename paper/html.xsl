<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
  version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:ltx="http://dlmf.nist.gov/LaTeXML"
  exclude-result-prefixes="ltx">

  <xsl:import href="urn:x-LaTeXML:XSLT:LaTeXML-html5.xsl"/>

  <xsl:param
    name="GOOGLE_SITE_VERIFICATION"
    select="'me5mvseR6ptdS0BZ_wss6pUWq4Wjj3Tdhz166JAic_w'"/>

  <xsl:template match="/" mode="head-end">
    <meta
      name="google-site-verification"
      content="{$GOOGLE_SITE_VERIFICATION}"/>
  </xsl:template>

  <xsl:template match="ltx:abstract">
    <xsl:param name="context"/>
    <xsl:text>&#x0A;</xsl:text>
    <xsl:element name="section" namespace="{$html_ns}">
      <xsl:call-template name="add_id"/>
      <xsl:call-template name="add_attributes"/>
      <xsl:apply-templates select="." mode="begin">
        <xsl:with-param name="context" select="$context"/>
      </xsl:apply-templates>
      <xsl:if test="@name">
        <xsl:element name="h2" namespace="{$html_ns}">
          <xsl:variable name="innercontext" select="'inline'"/>
          <xsl:attribute name="class">ltx_title ltx_title_abstract</xsl:attribute>
          <xsl:apply-templates select="@name">
            <xsl:with-param name="context" select="$innercontext"/>
          </xsl:apply-templates>
        </xsl:element>
      </xsl:if>
      <xsl:apply-templates>
        <xsl:with-param name="context" select="$context"/>
      </xsl:apply-templates>
      <xsl:apply-templates select="." mode="end">
        <xsl:with-param name="context" select="$context"/>
      </xsl:apply-templates>
    </xsl:element>
    <xsl:text>&#x0A;</xsl:text>
  </xsl:template>

  <xsl:template match="ltx:theorem/ltx:title | ltx:proof/ltx:title">
    <xsl:param name="context"/>
    <xsl:element name="span" namespace="{$html_ns}">
      <xsl:variable name="innercontext" select="'inline'"/>
      <xsl:call-template name="add_id"/>
      <xsl:call-template name="add_attributes"/>
      <xsl:apply-templates select="." mode="begin">
        <xsl:with-param name="context" select="$innercontext"/>
      </xsl:apply-templates>
      <xsl:apply-templates>
        <xsl:with-param name="context" select="$innercontext"/>
      </xsl:apply-templates>
      <xsl:apply-templates select="." mode="end">
        <xsl:with-param name="context" select="$innercontext"/>
      </xsl:apply-templates>
    </xsl:element>
  </xsl:template>

  <xsl:template match="ltx:td[@thead]" mode="begin">
    <xsl:attribute name="scope">
      <xsl:choose>
        <xsl:when test="ancestor::ltx:thead">col</xsl:when>
        <xsl:otherwise>row</xsl:otherwise>
      </xsl:choose>
    </xsl:attribute>
  </xsl:template>

  <xsl:template match="ltx:listing">
    <xsl:param name="context"/>
    <xsl:text>&#x0A;</xsl:text>
    <xsl:element name="div" namespace="{$html_ns}">
      <xsl:call-template name="add_id"/>
      <xsl:call-template name="add_attributes"/>
      <xsl:apply-templates select="." mode="begin">
        <xsl:with-param name="context" select="$context"/>
      </xsl:apply-templates>
      <xsl:element name="pre" namespace="{$html_ns}">
        <xsl:attribute name="class">ltx_listing_code</xsl:attribute>
        <xsl:element name="code" namespace="{$html_ns}">
          <xsl:for-each select="ltx:listingline">
            <xsl:element name="span" namespace="{$html_ns}">
              <xsl:call-template name="add_id"/>
              <xsl:call-template name="add_attributes"/>
              <xsl:apply-templates/>
            </xsl:element>
            <xsl:text>&#x0A;</xsl:text>
          </xsl:for-each>
        </xsl:element>
      </xsl:element>
      <xsl:apply-templates select="." mode="end">
        <xsl:with-param name="context" select="$context"/>
      </xsl:apply-templates>
    </xsl:element>
    <xsl:text>&#x0A;</xsl:text>
  </xsl:template>

  <xsl:template match="ltx:listing[@data and string-length(@dataname) &gt; 0]" mode="begin">
    <xsl:element name="div" namespace="{$html_ns}">
      <xsl:attribute name="class">ltx_listing_data</xsl:attribute>
      <xsl:element name="a" namespace="{$html_ns}">
        <xsl:call-template name="add_data_attribute">
          <xsl:with-param name="name" select="'href'"/>
        </xsl:call-template>
        <xsl:attribute name="download"><xsl:value-of select="@dataname"/></xsl:attribute>
        <xsl:text>Download the listing (</xsl:text>
        <xsl:value-of select="@dataname"/>
        <xsl:text>)</xsl:text>
      </xsl:element>
    </xsl:element>
  </xsl:template>

  <xsl:template match="ltx:listing[@data and string-length(@dataname) = 0]" mode="begin"/>

  <xsl:template match="/" mode="footer"/>

</xsl:stylesheet>
