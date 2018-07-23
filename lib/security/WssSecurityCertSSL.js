"use strict";

var fs = require('fs');
var path = require('path');
var ejs = require('ejs');
var SignedXml = require('xml-crypto').SignedXml;
var uuid4 = require('uuid/v4');
var wsseSecurityHeaderTemplate;
var wsseSecurityTokenTemplate;
var https = require('https');
var _ = require('lodash');

function addMinutes(date, minutes) {
  return new Date(date.getTime() + minutes * 60000);
}

function dateStringForSOAP(date) {
  return date.getUTCFullYear() + '-' + ('0' + (date.getUTCMonth() + 1)).slice(-2) + '-' +
    ('0' + date.getUTCDate()).slice(-2) + 'T' + ('0' + date.getUTCHours()).slice(-2) + ":" +
    ('0' + date.getUTCMinutes()).slice(-2) + ":" + ('0' + date.getUTCSeconds()).slice(-2) + "Z";
}

function generateCreated() {
  return dateStringForSOAP(new Date());
}

function generateExpires() {
  return dateStringForSOAP(addMinutes(new Date(), 10));
}

function insertStr(src, dst, pos) {
  return [dst.slice(0, pos), src, dst.slice(pos)].join('');
}

function generateId() {
  return uuid4().replace(/-/gm, '');
}

function WSSecurityCertSSL(privatePEM, publicP12PEM, password, key, cert, ca, defaults) {
  this.publicP12PEM = publicP12PEM.toString().replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE-----', '').replace(/(\r\n|\n|\r)/gm, '');

  this.signer = new SignedXml();
  this.signer.signingKey = {
    key: privatePEM,
    passphrase: password
  };
  this.x509Id = "x509-" + generateId();

  var _this = this;
  this.signer.keyInfoProvider = {};
  this.signer.keyInfoProvider.getKeyInfo = function (key) {
    if (!wsseSecurityTokenTemplate) {
      wsseSecurityTokenTemplate = ejs.compile(fs.readFileSync(path.join(__dirname, 'templates', 'wsse-security-token.ejs')).toString());
    }

    return wsseSecurityTokenTemplate({ x509Id: _this.x509Id });
  };

  if (key) {
    if(Buffer.isBuffer(key)) {
      this.key = key;
    } else if (typeof key === 'string') {
      this.key = fs.readFileSync(key);
    } else {
      throw new Error('key should be a buffer or a string!');
    }
  }

  if (cert) {
    if(Buffer.isBuffer(cert)) {
      this.cert = cert;
    } else if (typeof cert === 'string') {
      this.cert = fs.readFileSync(cert);
    } else {
      throw new Error('cert should be a buffer or a string!');
    }
  }

  if (ca) {
    if(Buffer.isBuffer(ca) || Array.isArray(ca)) {
      this.ca = ca;
    } else if (typeof ca === 'string') {
      this.ca = fs.readFileSync(ca);
    } else {
      defaults = ca;
      this.ca = null;
    }
  }

  this.defaults = {};
  _.merge(this.defaults, defaults);

  this.agent = null;
}

WSSecurityCertSSL.prototype.postProcess = function (xml, envelopeKey) {
  this.created = generateCreated();
  this.expires = generateExpires();

  if (!wsseSecurityHeaderTemplate) {
    wsseSecurityHeaderTemplate = ejs.compile(fs.readFileSync(path.join(__dirname, 'templates', 'wsse-security-header.ejs')).toString());
  }

  var secHeader = wsseSecurityHeaderTemplate({
    binaryToken: this.publicP12PEM,
    created: this.created,
    expires: this.expires,
    id: this.x509Id
  });

  var xmlWithSec = insertStr(secHeader, xml, xml.indexOf('</soap:Header>'));

  var references = ["http://www.w3.org/2000/09/xmldsig#enveloped-signature",
    "http://www.w3.org/2001/10/xml-exc-c14n#"];

  this.signer.addReference("//*[name(.)='" + envelopeKey + ":Body']", references);
  this.signer.addReference("//*[name(.)='wsse:Security']/*[local-name(.)='Timestamp']", references);

  this.signer.computeSignature(xmlWithSec);

  return insertStr(this.signer.getSignatureXml(), xmlWithSec, xmlWithSec.indexOf('</wsse:Security>'));
};

WSSecurityCertSSL.prototype.toXML = function(headers) {
  return '';
};

WSSecurityCertSSL.prototype.addOptions = function(options) {
  var httpsAgent = null;

  options.key = this.key;
  options.cert = this.cert;
  options.ca = this.ca;
  _.merge(options, this.defaults);

  if (!!options.forever) {
    if (!this.agent) {
      options.keepAlive = true;

      this.agent = new https.Agent(options);
    }

    httpsAgent = this.agent;
  } else {
    httpsAgent = new https.Agent(options);
  }

  options.agent = httpsAgent;
};

module.exports = WSSecurityCertSSL;
