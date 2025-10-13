<?xml version='1.0'?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:ss="http://docbook.sf.net/xmlns/string.subst/1.0" version="1.0">
  <xsl:import href="http://docbook.sourceforge.net/release/xsl-ns/current/manpages/profile-docbook.xsl"/>
  <xsl:param name="version"/>
  <xsl:param name="man.string.subst.map.local.pre">
    <ss:substitution oldstring="%version%" newstring="{$version}" />
  </xsl:param>
</xsl:stylesheet>
