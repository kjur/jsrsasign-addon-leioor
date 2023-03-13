const VERSION = "0.9.1";
const VERSION_FULL = "jsrsasign-addon-leioor 0.9.1 (c) Kenji Urushima github.com/kjur/jsrsasign-addon-leioor";

const OIDs = {
    "LEI":		"1.3.6.1.4.1.52266.1",
    "Role":		"1.3.6.1.4.1.52266.2"
};

let _KJUR = null;
let _X509 = null;
let _ASN1HEX = null;

function register(jsrsasign) {
    registerParts(jsrsasign.KJUR, jsrsasign.X509, jsrsasign.ASN1HEX);
}

function registerParts(argKJUR, argX509, argASN1HEX) {
    _KJUR = argKJUR;
    _X509 = argX509;
    _ASN1HEX = argASN1HEX;
    _KJUR.asn1.x509.OID.registerOIDs(OIDs);
    _X509.registExtParser("1.3.6.1.4.1.52266.1", extParserLEI);
    _X509.registExtParser("1.3.6.1.4.1.52266.2", extParserOOR);
}

function extParserLEI(oid, critical, hExtV) {
    try {
	let pExtV = _ASN1HEX.parse(hExtV);
	var result = {
	    extname: _KJUR.asn1.x509.OID.oid2name(oid),
	    value: pExtV.prnstr.str
	};
	if (critical) result.critical = true;
	return result;
    } catch(ex) {
	return undefined;
    }
}

function extParserOOR(oid, critical, hExtV) {
    try {
	let pExtV = _ASN1HEX.parse(hExtV);
	var result = {
	    extname: _KJUR.asn1.x509.OID.oid2name(oid),
	    value: pExtV.prnstr.str
	};
	if (critical) result.critical = true;
	return result;
    } catch(ex) {
	return undefined;
    }
}

exports.VERSION = VERSION;
exports.VERSION_FULL = VERSION_FULL;
exports.OIDs = OIDs;
exports.register = register;
exports.registerParts = registerParts;
