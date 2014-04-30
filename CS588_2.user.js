// ==UserScript==
// @namespace Modhi-Anshika
// @name Modhi-Anshika
// @description This project is based on a cryptography project given in CS255 at Stanford University, the instruction of the project and the starter script is available on the course website found at [insert link here]. To make use of this script, download Greacemonkey and Firefox..
// @version 1.1
//
// @include http://www.facebook.com/*
// @include https://www.facebook.com/*
// @exclude http://www.facebook.com/messages/*
// @exclude https://www.facebook.com/messages/*
// @exclude http://www.facebook.com/events/*
// @exclude https://www.facebook.com/events/*
// ==/UserScript==

// Strict mode makes it easier to catch errors.
// You may comment this out if you want.
// See http://ejohn.org/blog/ecmascript-5-strict-mode-json-and-more/
"use strict";
//-------------------------------------------------------------------------------
var my_username = null; // user name of the facebook account is fetched from the browser
var keys = {}; // association map of keys: group -> key
var dbPassword = null;
//-------------------------------------------------------------------------------

// Some initialization functions are called at the very end of this script.

// Return the encryption of the message for the given group, in the form of a string.
//
// @param {String} plainText String to encrypt.
// @param {String} group Group name.
// @return {String} Encryption of the plaintext, encoded as a string.
function Encrypt(plainText, group) {
  if(!(group in keys)){
	alert(group+" does not have a key! Assign a key for this group in Settings.")
	return;
	}
  var key = keys[group];
  var encrypted = CryptoJS.AES.encrypt(plainText, key);
  var hashInteger = CryptoJS.SHA3(plainText);
  localStorage.setItem("facebook-messages-" + my_username + plainText, encodeURIComponent(hashInteger));
  return encrypted;
}

// Return the decryption of the message for the given group, in the form of a string.
// Throws an error in case the string is not properly encrypted.
//
// @param {String} cipherText String to decrypt.
// @param {String} group Group name.
// @return {String} Decryption of the ciphertext.
function Decrypt(cipherText, group) {
  if(!(group in keys))
    throw "This group does not not have a key. Cannot decrypt message.";

  var key = keys[group];
  var decrypted = CryptoJS.AES.decrypt(cipherText, key);
  var hashInteger = localStorage.getItem("facebook-messages-" + my_username + decrypted.toString(CryptoJS.enc.Utf8));
  hashInteger = decodeURIComponent(hashInteger);
  var newHashInteger = CryptoJS.SHA3(decrypted.toString(CryptoJS.enc.Utf8));
  if (hashInteger == newHashInteger) {
    //alert("Message Intact");
  }
  else {
    //alert("Message changed");
    throw "Message authentication failed. Message changed.";
  }
  return decrypted.toString(CryptoJS.enc.Utf8);
}

// Generate a new key for the given group.
//
// @param {String} group Group name.
function GenerateKey(group) {
    var buf = new Uint8Array(1);
	window.crypto.getRandomValues(buf);
	var key = buf[0];
	keys[group] = key.toString();
  SaveKeys();
	alert("New key added for "+group+" with value "+key);
}

// Take the current group keys, and save them to disk.
function GetDbPassKey() {
  if (my_username != null) {
    var dbPass = localStorage.getItem('facebook-dbPass-' + my_username);
    if(dbPass != null){
      var dbPassword = decodeURIComponent(dbPass);
      return dbPassword;
    }
    dbPassword = prompt("DataBase Password:");
    if(dbPassword == null) {
      alert("Please enter a valid password to unlock database!");
      throw "!!Not A Valid Password!!";
    }
    localStorage.setItem('facebook-dbPass-' + my_username, encodeURIComponent(dbPassword));
    return dbPassword;
  }
}

function SaveKeys() {
  var dbPass = GetDbPassKey();
  var key_str = JSON.stringify(keys);
  var integerHash = CryptoJS.SHA3(key_str);
  var encryptedDB = CryptoJS.AES.encrypt(key_str, dbPass);
  localStorage.setItem('facebook-keys-' + my_username, encodeURIComponent(encryptedDB));
  localStorage.setItem('facebook-hash-' + my_username, encodeURIComponent(integerHash));
}

// Load the group keys from disk.
function LoadKeys() {
//localStorage.clear();
  var dbPass = GetDbPassKey();	
  assert(my_username != undefined);
  keys = {}; // Reset the keys.
  
  var saved = localStorage.getItem('facebook-keys-' + my_username);
  var integerHash = localStorage.getItem('facebook-hash-' + my_username);
  integerHash = decodeURIComponent(integerHash);
  if (saved) {
    var encryptedDB = decodeURIComponent(saved);
    var decryptedDB = CryptoJS.AES.decrypt(encryptedDB, dbPass);
    //alert("key"+dbPass+" ***"+encryptedDB+" @@"+decryptedDB);
    // CS255-todo: plaintext keys were on disk?
    var keyString = decryptedDB.toString(CryptoJS.enc.Utf8);
    var newHashInteger = CryptoJS.SHA3(keyString);
    if (integerHash == newHashInteger) {
      alert("Keys intact");
    }
    else {
      alert("WARNING! Keys changed!!");
      return;
    }
    //alert(keyString);
    keys = JSON.parse(keyString);
  }
  
}


/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////
//
// Using the AES primitives from CryptoJS v3.1.2
//
/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////

//---------------------------------------------------------------
/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
var CryptoJS=CryptoJS||function(u,p){var d={},l=d.lib={},s=function(){},t=l.Base={extend:function(a){s.prototype=this;var c=new s;a&&c.mixIn(a);c.hasOwnProperty("init")||(c.init=function(){c.$super.init.apply(this,arguments)});c.init.prototype=c;c.$super=this;return c},create:function(){var a=this.extend();a.init.apply(a,arguments);return a},init:function(){},mixIn:function(a){for(var c in a)a.hasOwnProperty(c)&&(this[c]=a[c]);a.hasOwnProperty("toString")&&(this.toString=a.toString)},clone:function(){return this.init.prototype.extend(this)}},
r=l.WordArray=t.extend({init:function(a,c){a=this.words=a||[];this.sigBytes=c!=p?c:4*a.length},toString:function(a){return(a||v).stringify(this)},concat:function(a){var c=this.words,e=a.words,j=this.sigBytes;a=a.sigBytes;this.clamp();if(j%4)for(var k=0;k<a;k++)c[j+k>>>2]|=(e[k>>>2]>>>24-8*(k%4)&255)<<24-8*((j+k)%4);else if(65535<e.length)for(k=0;k<a;k+=4)c[j+k>>>2]=e[k>>>2];else c.push.apply(c,e);this.sigBytes+=a;return this},clamp:function(){var a=this.words,c=this.sigBytes;a[c>>>2]&=4294967295<<
32-8*(c%4);a.length=u.ceil(c/4)},clone:function(){var a=t.clone.call(this);a.words=this.words.slice(0);return a},random:function(a){for(var c=[],e=0;e<a;e+=4)c.push(4294967296*u.random()|0);return new r.init(c,a)}}),w=d.enc={},v=w.Hex={stringify:function(a){var c=a.words;a=a.sigBytes;for(var e=[],j=0;j<a;j++){var k=c[j>>>2]>>>24-8*(j%4)&255;e.push((k>>>4).toString(16));e.push((k&15).toString(16))}return e.join("")},parse:function(a){for(var c=a.length,e=[],j=0;j<c;j+=2)e[j>>>3]|=parseInt(a.substr(j,
2),16)<<24-4*(j%8);return new r.init(e,c/2)}},b=w.Latin1={stringify:function(a){var c=a.words;a=a.sigBytes;for(var e=[],j=0;j<a;j++)e.push(String.fromCharCode(c[j>>>2]>>>24-8*(j%4)&255));return e.join("")},parse:function(a){for(var c=a.length,e=[],j=0;j<c;j++)e[j>>>2]|=(a.charCodeAt(j)&255)<<24-8*(j%4);return new r.init(e,c)}},x=w.Utf8={stringify:function(a){try{return decodeURIComponent(escape(b.stringify(a)))}catch(c){throw Error("Malformed UTF-8 data");}},parse:function(a){return b.parse(unescape(encodeURIComponent(a)))}},
q=l.BufferedBlockAlgorithm=t.extend({reset:function(){this._data=new r.init;this._nDataBytes=0},_append:function(a){"string"==typeof a&&(a=x.parse(a));this._data.concat(a);this._nDataBytes+=a.sigBytes},_process:function(a){var c=this._data,e=c.words,j=c.sigBytes,k=this.blockSize,b=j/(4*k),b=a?u.ceil(b):u.max((b|0)-this._minBufferSize,0);a=b*k;j=u.min(4*a,j);if(a){for(var q=0;q<a;q+=k)this._doProcessBlock(e,q);q=e.splice(0,a);c.sigBytes-=j}return new r.init(q,j)},clone:function(){var a=t.clone.call(this);
a._data=this._data.clone();return a},_minBufferSize:0});l.Hasher=q.extend({cfg:t.extend(),init:function(a){this.cfg=this.cfg.extend(a);this.reset()},reset:function(){q.reset.call(this);this._doReset()},update:function(a){this._append(a);this._process();return this},finalize:function(a){a&&this._append(a);return this._doFinalize()},blockSize:16,_createHelper:function(a){return function(b,e){return(new a.init(e)).finalize(b)}},_createHmacHelper:function(a){return function(b,e){return(new n.HMAC.init(a,
e)).finalize(b)}}});var n=d.algo={};return d}(Math);
(function(){var u=CryptoJS,p=u.lib.WordArray;u.enc.Base64={stringify:function(d){var l=d.words,p=d.sigBytes,t=this._map;d.clamp();d=[];for(var r=0;r<p;r+=3)for(var w=(l[r>>>2]>>>24-8*(r%4)&255)<<16|(l[r+1>>>2]>>>24-8*((r+1)%4)&255)<<8|l[r+2>>>2]>>>24-8*((r+2)%4)&255,v=0;4>v&&r+0.75*v<p;v++)d.push(t.charAt(w>>>6*(3-v)&63));if(l=t.charAt(64))for(;d.length%4;)d.push(l);return d.join("")},parse:function(d){var l=d.length,s=this._map,t=s.charAt(64);t&&(t=d.indexOf(t),-1!=t&&(l=t));for(var t=[],r=0,w=0;w<
l;w++)if(w%4){var v=s.indexOf(d.charAt(w-1))<<2*(w%4),b=s.indexOf(d.charAt(w))>>>6-2*(w%4);t[r>>>2]|=(v|b)<<24-8*(r%4);r++}return p.create(t,r)},_map:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="}})();
(function(u){function p(b,n,a,c,e,j,k){b=b+(n&a|~n&c)+e+k;return(b<<j|b>>>32-j)+n}function d(b,n,a,c,e,j,k){b=b+(n&c|a&~c)+e+k;return(b<<j|b>>>32-j)+n}function l(b,n,a,c,e,j,k){b=b+(n^a^c)+e+k;return(b<<j|b>>>32-j)+n}function s(b,n,a,c,e,j,k){b=b+(a^(n|~c))+e+k;return(b<<j|b>>>32-j)+n}for(var t=CryptoJS,r=t.lib,w=r.WordArray,v=r.Hasher,r=t.algo,b=[],x=0;64>x;x++)b[x]=4294967296*u.abs(u.sin(x+1))|0;r=r.MD5=v.extend({_doReset:function(){this._hash=new w.init([1732584193,4023233417,2562383102,271733878])},
_doProcessBlock:function(q,n){for(var a=0;16>a;a++){var c=n+a,e=q[c];q[c]=(e<<8|e>>>24)&16711935|(e<<24|e>>>8)&4278255360}var a=this._hash.words,c=q[n+0],e=q[n+1],j=q[n+2],k=q[n+3],z=q[n+4],r=q[n+5],t=q[n+6],w=q[n+7],v=q[n+8],A=q[n+9],B=q[n+10],C=q[n+11],u=q[n+12],D=q[n+13],E=q[n+14],x=q[n+15],f=a[0],m=a[1],g=a[2],h=a[3],f=p(f,m,g,h,c,7,b[0]),h=p(h,f,m,g,e,12,b[1]),g=p(g,h,f,m,j,17,b[2]),m=p(m,g,h,f,k,22,b[3]),f=p(f,m,g,h,z,7,b[4]),h=p(h,f,m,g,r,12,b[5]),g=p(g,h,f,m,t,17,b[6]),m=p(m,g,h,f,w,22,b[7]),
f=p(f,m,g,h,v,7,b[8]),h=p(h,f,m,g,A,12,b[9]),g=p(g,h,f,m,B,17,b[10]),m=p(m,g,h,f,C,22,b[11]),f=p(f,m,g,h,u,7,b[12]),h=p(h,f,m,g,D,12,b[13]),g=p(g,h,f,m,E,17,b[14]),m=p(m,g,h,f,x,22,b[15]),f=d(f,m,g,h,e,5,b[16]),h=d(h,f,m,g,t,9,b[17]),g=d(g,h,f,m,C,14,b[18]),m=d(m,g,h,f,c,20,b[19]),f=d(f,m,g,h,r,5,b[20]),h=d(h,f,m,g,B,9,b[21]),g=d(g,h,f,m,x,14,b[22]),m=d(m,g,h,f,z,20,b[23]),f=d(f,m,g,h,A,5,b[24]),h=d(h,f,m,g,E,9,b[25]),g=d(g,h,f,m,k,14,b[26]),m=d(m,g,h,f,v,20,b[27]),f=d(f,m,g,h,D,5,b[28]),h=d(h,f,
m,g,j,9,b[29]),g=d(g,h,f,m,w,14,b[30]),m=d(m,g,h,f,u,20,b[31]),f=l(f,m,g,h,r,4,b[32]),h=l(h,f,m,g,v,11,b[33]),g=l(g,h,f,m,C,16,b[34]),m=l(m,g,h,f,E,23,b[35]),f=l(f,m,g,h,e,4,b[36]),h=l(h,f,m,g,z,11,b[37]),g=l(g,h,f,m,w,16,b[38]),m=l(m,g,h,f,B,23,b[39]),f=l(f,m,g,h,D,4,b[40]),h=l(h,f,m,g,c,11,b[41]),g=l(g,h,f,m,k,16,b[42]),m=l(m,g,h,f,t,23,b[43]),f=l(f,m,g,h,A,4,b[44]),h=l(h,f,m,g,u,11,b[45]),g=l(g,h,f,m,x,16,b[46]),m=l(m,g,h,f,j,23,b[47]),f=s(f,m,g,h,c,6,b[48]),h=s(h,f,m,g,w,10,b[49]),g=s(g,h,f,m,
E,15,b[50]),m=s(m,g,h,f,r,21,b[51]),f=s(f,m,g,h,u,6,b[52]),h=s(h,f,m,g,k,10,b[53]),g=s(g,h,f,m,B,15,b[54]),m=s(m,g,h,f,e,21,b[55]),f=s(f,m,g,h,v,6,b[56]),h=s(h,f,m,g,x,10,b[57]),g=s(g,h,f,m,t,15,b[58]),m=s(m,g,h,f,D,21,b[59]),f=s(f,m,g,h,z,6,b[60]),h=s(h,f,m,g,C,10,b[61]),g=s(g,h,f,m,j,15,b[62]),m=s(m,g,h,f,A,21,b[63]);a[0]=a[0]+f|0;a[1]=a[1]+m|0;a[2]=a[2]+g|0;a[3]=a[3]+h|0},_doFinalize:function(){var b=this._data,n=b.words,a=8*this._nDataBytes,c=8*b.sigBytes;n[c>>>5]|=128<<24-c%32;var e=u.floor(a/
4294967296);n[(c+64>>>9<<4)+15]=(e<<8|e>>>24)&16711935|(e<<24|e>>>8)&4278255360;n[(c+64>>>9<<4)+14]=(a<<8|a>>>24)&16711935|(a<<24|a>>>8)&4278255360;b.sigBytes=4*(n.length+1);this._process();b=this._hash;n=b.words;for(a=0;4>a;a++)c=n[a],n[a]=(c<<8|c>>>24)&16711935|(c<<24|c>>>8)&4278255360;return b},clone:function(){var b=v.clone.call(this);b._hash=this._hash.clone();return b}});t.MD5=v._createHelper(r);t.HmacMD5=v._createHmacHelper(r)})(Math);
(function(){var u=CryptoJS,p=u.lib,d=p.Base,l=p.WordArray,p=u.algo,s=p.EvpKDF=d.extend({cfg:d.extend({keySize:4,hasher:p.MD5,iterations:1}),init:function(d){this.cfg=this.cfg.extend(d)},compute:function(d,r){for(var p=this.cfg,s=p.hasher.create(),b=l.create(),u=b.words,q=p.keySize,p=p.iterations;u.length<q;){n&&s.update(n);var n=s.update(d).finalize(r);s.reset();for(var a=1;a<p;a++)n=s.finalize(n),s.reset();b.concat(n)}b.sigBytes=4*q;return b}});u.EvpKDF=function(d,l,p){return s.create(p).compute(d,
l)}})();
CryptoJS.lib.Cipher||function(u){var p=CryptoJS,d=p.lib,l=d.Base,s=d.WordArray,t=d.BufferedBlockAlgorithm,r=p.enc.Base64,w=p.algo.EvpKDF,v=d.Cipher=t.extend({cfg:l.extend(),createEncryptor:function(e,a){return this.create(this._ENC_XFORM_MODE,e,a)},createDecryptor:function(e,a){return this.create(this._DEC_XFORM_MODE,e,a)},init:function(e,a,b){this.cfg=this.cfg.extend(b);this._xformMode=e;this._key=a;this.reset()},reset:function(){t.reset.call(this);this._doReset()},process:function(e){this._append(e);return this._process()},
finalize:function(e){e&&this._append(e);return this._doFinalize()},keySize:4,ivSize:4,_ENC_XFORM_MODE:1,_DEC_XFORM_MODE:2,_createHelper:function(e){return{encrypt:function(b,k,d){return("string"==typeof k?c:a).encrypt(e,b,k,d)},decrypt:function(b,k,d){return("string"==typeof k?c:a).decrypt(e,b,k,d)}}}});d.StreamCipher=v.extend({_doFinalize:function(){return this._process(!0)},blockSize:1});var b=p.mode={},x=function(e,a,b){var c=this._iv;c?this._iv=u:c=this._prevBlock;for(var d=0;d<b;d++)e[a+d]^=
c[d]},q=(d.BlockCipherMode=l.extend({createEncryptor:function(e,a){return this.Encryptor.create(e,a)},createDecryptor:function(e,a){return this.Decryptor.create(e,a)},init:function(e,a){this._cipher=e;this._iv=a}})).extend();q.Encryptor=q.extend({processBlock:function(e,a){var b=this._cipher,c=b.blockSize;x.call(this,e,a,c);b.encryptBlock(e,a);this._prevBlock=e.slice(a,a+c)}});q.Decryptor=q.extend({processBlock:function(e,a){var b=this._cipher,c=b.blockSize,d=e.slice(a,a+c);b.decryptBlock(e,a);x.call(this,
e,a,c);this._prevBlock=d}});b=b.CBC=q;q=(p.pad={}).Pkcs7={pad:function(a,b){for(var c=4*b,c=c-a.sigBytes%c,d=c<<24|c<<16|c<<8|c,l=[],n=0;n<c;n+=4)l.push(d);c=s.create(l,c);a.concat(c)},unpad:function(a){a.sigBytes-=a.words[a.sigBytes-1>>>2]&255}};d.BlockCipher=v.extend({cfg:v.cfg.extend({mode:b,padding:q}),reset:function(){v.reset.call(this);var a=this.cfg,b=a.iv,a=a.mode;if(this._xformMode==this._ENC_XFORM_MODE)var c=a.createEncryptor;else c=a.createDecryptor,this._minBufferSize=1;this._mode=c.call(a,
this,b&&b.words)},_doProcessBlock:function(a,b){this._mode.processBlock(a,b)},_doFinalize:function(){var a=this.cfg.padding;if(this._xformMode==this._ENC_XFORM_MODE){a.pad(this._data,this.blockSize);var b=this._process(!0)}else b=this._process(!0),a.unpad(b);return b},blockSize:4});var n=d.CipherParams=l.extend({init:function(a){this.mixIn(a)},toString:function(a){return(a||this.formatter).stringify(this)}}),b=(p.format={}).OpenSSL={stringify:function(a){var b=a.ciphertext;a=a.salt;return(a?s.create([1398893684,
1701076831]).concat(a).concat(b):b).toString(r)},parse:function(a){a=r.parse(a);var b=a.words;if(1398893684==b[0]&&1701076831==b[1]){var c=s.create(b.slice(2,4));b.splice(0,4);a.sigBytes-=16}return n.create({ciphertext:a,salt:c})}},a=d.SerializableCipher=l.extend({cfg:l.extend({format:b}),encrypt:function(a,b,c,d){d=this.cfg.extend(d);var l=a.createEncryptor(c,d);b=l.finalize(b);l=l.cfg;return n.create({ciphertext:b,key:c,iv:l.iv,algorithm:a,mode:l.mode,padding:l.padding,blockSize:a.blockSize,formatter:d.format})},
decrypt:function(a,b,c,d){d=this.cfg.extend(d);b=this._parse(b,d.format);return a.createDecryptor(c,d).finalize(b.ciphertext)},_parse:function(a,b){return"string"==typeof a?b.parse(a,this):a}}),p=(p.kdf={}).OpenSSL={execute:function(a,b,c,d){d||(d=s.random(8));a=w.create({keySize:b+c}).compute(a,d);c=s.create(a.words.slice(b),4*c);a.sigBytes=4*b;return n.create({key:a,iv:c,salt:d})}},c=d.PasswordBasedCipher=a.extend({cfg:a.cfg.extend({kdf:p}),encrypt:function(b,c,d,l){l=this.cfg.extend(l);d=l.kdf.execute(d,
b.keySize,b.ivSize);l.iv=d.iv;b=a.encrypt.call(this,b,c,d.key,l);b.mixIn(d);return b},decrypt:function(b,c,d,l){l=this.cfg.extend(l);c=this._parse(c,l.format);d=l.kdf.execute(d,b.keySize,b.ivSize,c.salt);l.iv=d.iv;return a.decrypt.call(this,b,c,d.key,l)}})}();
(function(){for(var u=CryptoJS,p=u.lib.BlockCipher,d=u.algo,l=[],s=[],t=[],r=[],w=[],v=[],b=[],x=[],q=[],n=[],a=[],c=0;256>c;c++)a[c]=128>c?c<<1:c<<1^283;for(var e=0,j=0,c=0;256>c;c++){var k=j^j<<1^j<<2^j<<3^j<<4,k=k>>>8^k&255^99;l[e]=k;s[k]=e;var z=a[e],F=a[z],G=a[F],y=257*a[k]^16843008*k;t[e]=y<<24|y>>>8;r[e]=y<<16|y>>>16;w[e]=y<<8|y>>>24;v[e]=y;y=16843009*G^65537*F^257*z^16843008*e;b[k]=y<<24|y>>>8;x[k]=y<<16|y>>>16;q[k]=y<<8|y>>>24;n[k]=y;e?(e=z^a[a[a[G^z]]],j^=a[a[j]]):e=j=1}var H=[0,1,2,4,8,
16,32,64,128,27,54],d=d.AES=p.extend({_doReset:function(){for(var a=this._key,c=a.words,d=a.sigBytes/4,a=4*((this._nRounds=d+6)+1),e=this._keySchedule=[],j=0;j<a;j++)if(j<d)e[j]=c[j];else{var k=e[j-1];j%d?6<d&&4==j%d&&(k=l[k>>>24]<<24|l[k>>>16&255]<<16|l[k>>>8&255]<<8|l[k&255]):(k=k<<8|k>>>24,k=l[k>>>24]<<24|l[k>>>16&255]<<16|l[k>>>8&255]<<8|l[k&255],k^=H[j/d|0]<<24);e[j]=e[j-d]^k}c=this._invKeySchedule=[];for(d=0;d<a;d++)j=a-d,k=d%4?e[j]:e[j-4],c[d]=4>d||4>=j?k:b[l[k>>>24]]^x[l[k>>>16&255]]^q[l[k>>>
8&255]]^n[l[k&255]]},encryptBlock:function(a,b){this._doCryptBlock(a,b,this._keySchedule,t,r,w,v,l)},decryptBlock:function(a,c){var d=a[c+1];a[c+1]=a[c+3];a[c+3]=d;this._doCryptBlock(a,c,this._invKeySchedule,b,x,q,n,s);d=a[c+1];a[c+1]=a[c+3];a[c+3]=d},_doCryptBlock:function(a,b,c,d,e,j,l,f){for(var m=this._nRounds,g=a[b]^c[0],h=a[b+1]^c[1],k=a[b+2]^c[2],n=a[b+3]^c[3],p=4,r=1;r<m;r++)var q=d[g>>>24]^e[h>>>16&255]^j[k>>>8&255]^l[n&255]^c[p++],s=d[h>>>24]^e[k>>>16&255]^j[n>>>8&255]^l[g&255]^c[p++],t=
d[k>>>24]^e[n>>>16&255]^j[g>>>8&255]^l[h&255]^c[p++],n=d[n>>>24]^e[g>>>16&255]^j[h>>>8&255]^l[k&255]^c[p++],g=q,h=s,k=t;q=(f[g>>>24]<<24|f[h>>>16&255]<<16|f[k>>>8&255]<<8|f[n&255])^c[p++];s=(f[h>>>24]<<24|f[k>>>16&255]<<16|f[n>>>8&255]<<8|f[g&255])^c[p++];t=(f[k>>>24]<<24|f[n>>>16&255]<<16|f[g>>>8&255]<<8|f[h&255])^c[p++];n=(f[n>>>24]<<24|f[g>>>16&255]<<16|f[h>>>8&255]<<8|f[k&255])^c[p++];a[b]=q;a[b+1]=s;a[b+2]=t;a[b+3]=n},keySize:8});u.AES=p._createHelper(d)})();

//---------------------------------------------------------------

/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
var CryptoJS=CryptoJS||function(v,p){
  var d={},
  u=d.lib={},
  r=function(){},
  f=u.Base={
    extend:function(a){
      r.prototype=this;
      var b=new r;
      a&&b.mixIn(a);
      b.hasOwnProperty("init")||(b.init=function(){b.$super.init.apply(this,arguments)});
      b.init.prototype=b;
      b.$super=this;return b
    },
    create:function(){
      var a=this.extend();
      a.init.apply(a,arguments);
      return a
    },
    init:function(){},
    mixIn:function(a){
      for(var b in a)
        a.hasOwnProperty(b)&&(this[b]=a[b]);
      a.hasOwnProperty("toString")&&(this.toString=a.toString)
    },
    clone:function(){
      return this.init.prototype.extend(this)
    }
  },
  s=u.WordArray=f.extend({
    init:function(a,b){
      a=this.words=a||[];
      this.sigBytes=b!=p?b:4*a.length
    },
    toString:function(a){
      return(a||y).stringify(this)
    },
    concat:function(a){
      var b=this.words,c=a.words,j=this.sigBytes;
      a=a.sigBytes;
      this.clamp();
      if(j%4)
        for(var n=0;n<a;n++)
          b[j+n>>>2]|=(c[n>>>2]>>>24-8*(n%4)&255)<<24-8*((j+n)%4);
      else if(65535<c.length)
        for(n=0;n<a;n+=4)
          b[j+n>>>2]=c[n>>>2];
      else 
        b.push.apply(b,c);
      this.sigBytes+=a;
      return this
    },
    clamp:function(){
      var a=this.words,b=this.sigBytes;
      a[b>>>2]&=4294967295<<32-8*(b%4);
      a.length=v.ceil(b/4)
    },
    clone:function(){
      var a=f.clone.call(this);
      a.words=this.words.slice(0);
      return a
    },
    random:function(a){
      for(var b=[],c=0;c<a;c+=4)
        b.push(4294967296*v.random()|0);
      return new s.init(b,a)
    }
  }),
  x=d.enc={},
  y=x.Hex={
    stringify:function(a){
      var b=a.words;
      a=a.sigBytes;
      for(var c=[],j=0;j<a;j++){
        var n=b[j>>>2]>>>24-8*(j%4)&255;
        c.push((n>>>4).toString(16));
        c.push((n&15).toString(16))
      }
      return c.join("")
    },
    parse:function(a){
      for(var b=a.length,c=[],j=0;j<b;j+=2)
        c[j>>>3]|=parseInt(a.substr(j,2),16)<<24-4*(j%8);
      return new s.init(c,b/2)
    }
  },
  e=x.Latin1={
    stringify:function(a){
      var b=a.words;
      a=a.sigBytes;
      for(var c=[],j=0;j<a;j++)
        c.push(String.fromCharCode(b[j>>>2]>>>24-8*(j%4)&255));
      return c.join("")
    },
    parse:function(a){
      for(var b=a.length,c=[],j=0;j<b;j++)
        c[j>>>2]|=(a.charCodeAt(j)&255)<<24-8*(j%4);
      return new s.init(c,b)
    }
  },
  q=x.Utf8={
    stringify:function(a){
      try{
        return decodeURIComponent(escape(e.stringify(a)))
      }
      catch(b){
        throw Error("Malformed UTF-8 data");
      }
    },
    parse:function(a){
      return e.parse(unescape(encodeURIComponent(a)))
    }
  },
  t=u.BufferedBlockAlgorithm=f.extend({
    reset:function(){
      this._data=new s.init;
      this._nDataBytes=0
    },
    _append:function(a){
      "string"==typeof a&&(a=q.parse(a));
      this._data.concat(a);
      this._nDataBytes+=a.sigBytes
    },
    _process:function(a){
      var b=this._data,c=b.words,j=b.sigBytes,n=this.blockSize,e=j/(4*n),e=a?v.ceil(e):v.max((e|0)-this._minBufferSize,0);
      a=e*n;
      j=v.min(4*a,j);
      if(a){
        for(var f=0;f<a;f+=n)
          this._doProcessBlock(c,f);
        f=c.splice(0,a);
        b.sigBytes-=j
      }
      return new s.init(f,j)
    },
    clone:function(){
      var a=f.clone.call(this);
      a._data=this._data.clone();
      return a
    },
    _minBufferSize:0
  });
  u.Hasher=t.extend({
    cfg:f.extend(),
    init:function(a){
      this.cfg=this.cfg.extend(a);
      this.reset()
    },
    reset:function(){
      t.reset.call(this);
      this._doReset()
    },
    update:function(a){
      this._append(a);
      this._process();
      return this
    },
    finalize:function(a){
      a&&this._append(a);
      return this._doFinalize()
    },
    blockSize:16,
    _createHelper:function(a){
      return function(b,c){
        return(new a.init(c)).finalize(b)
      }
    },
    _createHmacHelper:function(a){
      return function(b,c){
        return(new w.HMAC.init(a,c)).finalize(b)
      }
    }
  });
  var w=d.algo={};
  return d
}(Math);

(function(v){
  var p=CryptoJS,d=p.lib,u=d.Base,r=d.WordArray,p=p.x64={};
  p.Word=u.extend({
    init:function(f,s){
      this.high=f;
      this.low=s
    }
  });
  p.WordArray=u.extend({
    init:function(f,s){
      f=this.words=f||[];
      this.sigBytes=s!=v?s:8*f.length
    },
    toX32:function(){
      for(var f=this.words,s=f.length,d=[],p=0;p<s;p++){
        var e=f[p];
        d.push(e.high);
        d.push(e.low)
      }
      return r.create(d,this.sigBytes)
    },
    clone:function(){
      for(var f=u.clone.call(this),d=f.words=this.words.slice(0),p=d.length,r=0;r<p;r++)
        d[r]=d[r].clone();
      return f
    }
  })
})();

(function(v){
  for(var p=CryptoJS,d=p.lib,u=d.WordArray,r=d.Hasher,f=p.x64.Word,d=p.algo,s=[],x=[],y=[],e=1,q=0,t=0;24>t;t++){
    s[e+5*q]=(t+1)*(t+2)/2%64;
    var w=(2*e+3*q)%5,e=q%5,q=w
  }
  for(e=0;5>e;e++)
    for(q=0;5>q;q++)
      x[e+5*q]=q+5*((2*e+3*q)%5);
  e=1;
  for(q=0;24>q;q++){
    for(var a=w=t=0;7>a;a++){
      if(e&1){
        var b=(1<<a)-1;32>b?w^=1<<b:t^=1<<b-32
      }
      e=e&128?e<<1^113:e<<1
    }
    y[q]=f.create(t,w)
  }
  for(var c=[],e=0;25>e;e++)
    c[e]=f.create();
  d=d.SHA3=r.extend({
    cfg:r.cfg.extend({
      outputLength:512
    }),
    _doReset:function(){
      for(var a=this._state=[],b=0;25>b;b++)
        a[b]=new f.init;
      this.blockSize=(1600-2*this.cfg.outputLength)/32
    },
    _doProcessBlock:function(a,b){
      for(var e=this._state,f=this.blockSize/2,h=0;h<f;h++){
        var l=a[b+2*h],m=a[b+2*h+1],l=(l<<8|l>>>24)&16711935|(l<<24|l>>>8)&4278255360,m=(m<<8|m>>>24)&16711935|(m<<24|m>>>8)&4278255360,g=e[h];
        g.high^=m;
        g.low^=l
      }
      for(f=0;24>f;f++){
        for(h=0;5>h;h++){
          for(var d=l=0,k=0;5>k;k++)
            g=e[h+5*k],l^=g.high,d^=g.low;g=c[h];g.high=l;g.low=d
        }
        for(h=0;5>h;h++){
          g=c[(h+4)%5];
          l=c[(h+1)%5];
          m=l.high;
          k=l.low;
          l=g.high^(m<<1|k>>>31);
          d=g.low^(k<<1|m>>>31);
          for(k=0;5>k;k++)
            g=e[h+5*k],g.high^=l,g.low^=d
        }
        for(m=1;25>m;m++)
          g=e[m],h=g.high,g=g.low,k=s[m],32>k?(l=h<<k|g>>>32-k,d=g<<k|h>>>32-k):(l=g<<k-32|h>>>64-k,d=h<<k-32|g>>>64-k),g=c[x[m]],g.high=l,g.low=d;
        g=c[0];
        h=e[0];
        g.high=h.high;
        g.low=h.low;
        for(h=0;5>h;h++)
          for(k=0;5>k;k++)
            m=h+5*k,g=e[m],l=c[m],m=c[(h+1)%5+5*k],d=c[(h+2)%5+5*k],g.high=l.high^~m.high&d.high,g.low=l.low^~m.low&d.low;
        g=e[0];
        h=y[f];
        g.high^=h.high;
        g.low^=h.low
      }
    },
    _doFinalize:function(){
      var a=this._data,b=a.words,c=8*a.sigBytes,e=32*this.blockSize;
      b[c>>>5]|=1<<24-c%32;
      b[(v.ceil((c+1)/e)*e>>>5)-1]|=128;
      a.sigBytes=4*b.length;
      this._process();
      for(var a=this._state,b=this.cfg.outputLength/8,c=b/8,e=[],h=0;h<c;h++){
        var d=a[h],f=d.high,d=d.low,f=(f<<8|f>>>24)&16711935|(f<<24|f>>>8)&4278255360,d=(d<<8|d>>>24)&16711935|(d<<24|d>>>8)&4278255360;
        e.push(d);
        e.push(f)
      }
      return new u.init(e,b)
    },
    clone:function(){
      for(var a=r.clone.call(this),b=a._state=this._state.slice(0),c=0;25>c;c++)
        b[c]=b[c].clone();
      return a
    }
  });
  p.SHA3=r._createHelper(d);
  p.HmacSHA3=r._createHmacHelper(d)
})(Math);





// -----------------------------------------------------------

/*
Here are the basic cryptographic functions (implemented farther down)
you need to do the assignment:

function sjcl.cipher.aes(key)

This function creates a new AES encryptor/decryptor with a given key.
Note that the key must be an array of 4, 6, or 8 32-bit words for the
function to work. For those of you keeping score, this constructor does
all the scheduling needed for the cipher to work.

encrypt: function(plaintext)

This function encrypts the given plaintext. The plaintext argument
should take the form of an array of four (32-bit) integers, so the plaintext
should only be one block of data.

decrypt: function(ciphertext)

This function decrypts the given ciphertext. Again, the ciphertext argument
should be an array of 4 integers.

A silly example of this in action:

var key1 = new Array(8);
var cipher = new sjcl.cipher.aes(key1);
var dumbtext = new Array(4);
dumbtext[0] = 1; dumbtext[1] = 2; dumbtext[2] = 3; dumbtext[3] = 4;
var ctext = cipher.encrypt(dumbtext);
var outtext = cipher.decrypt(ctext);

Obviously our key is just all zeroes in this case, but this should illustrate
the point.
*/

/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////
//
// Should not _have_ to change anything below here.
// Helper functions and sample code.
//
/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////


// From http://aymanh.com/9-javascript-tips-you-may-not-know#Assertion
// Just in case you want an assert() function

function AssertException(message) {
  this.message = message;
}
AssertException.prototype.toString = function() {
  return 'AssertException: ' + this.message;
}

function assert(exp, message) {
  if (!exp) {
    throw new AssertException(message);
  }
}

// Very primitive encryption.

function SetupUsernames() {
  // get who you are logged in as
  var meta = document.getElementsByClassName('navItem firstItem tinyman litestandNavItem')[0];
  if (typeof meta !== "undefined") {
    var usernameMatched = /www.facebook.com\/(.*?)ref=tn_tnmn/i.exec(meta.innerHTML);
    usernameMatched = usernameMatched[1].replace(/&amp;/, '');
    usernameMatched = usernameMatched.replace(/\?/, '');
    usernameMatched = usernameMatched.replace(/profile\.phpid=/, '');
    my_username = usernameMatched; // Update global.
  }
}


function hasClass(element, cls) {
  var r = new RegExp('\\b' + cls + '\\b');
  return r.test(element.className);
}

function DocChanged(e) {
  if (document.URL.match(/groups/)) {
    //Check for adding encrypt button for comments
    if (e.target.nodeType != 3) {
      decryptTextOfChildNodes(e.target);
      decryptTextOfChildNodes2(e.target);
      if (!hasClass(e.target, "crypto")) {
        addEncryptCommentButton(e.target);
      } else {
        return;
      }
    }

    tryAddEncryptButton();
  }
  //Check for adding keys-table
  if (document.URL.match('settings')) {
    if (!document.getElementById('group-keys-table') && !hasClass(e.target, "crypto")) {
      AddEncryptionTab();
      UpdateKeysTable();
    }
  }
}
//Decryption of posts


function decryptTextOfChildNodes(e) {
  var msgs = e.getElementsByClassName('mbs _5pbx userContent');
  
  if (msgs.length > 0) {
	
    var msgs_array = new Array();
    for (var i = 0; i < msgs.length; ++i) {
      msgs_array[i] = msgs[i];
    }
    for (var i = 0; i < msgs_array.length; ++i) {
      DecryptMsg(msgs_array[i]);
    }
  }

}
//Decryption of comments


function decryptTextOfChildNodes2(e) {
  var msgs = e.getElementsByClassName('UFICommentBody');

  if (msgs.length > 0) {
    var msgs_array = new Array();
    for (var i = 0; i < msgs.length; ++i) {
      msgs_array[i] = msgs[i];
    }
    for (var i = 0; i < msgs_array.length; ++i) {
      DecryptMsg(msgs_array[i]);
    }
  }

}

function RegisterChangeEvents() {
  // Facebook loads posts dynamically using AJAX, so we monitor changes
  // to the HTML to discover new posts or comments.
  var doc = document.addEventListener("DOMNodeInserted", DocChanged, false);
}
// -------------------------DONE-----------------------------
function AddEncryptionTab() {

  // On the Account Settings page, show the key setups
  if (document.URL.match('settings')) {
    var div = document.getElementById('contentArea');
    if (div) {
      var h2 = document.createElement('h2');
      h2.setAttribute("class", "crypto");
      h2.innerHTML = "Encryption Keys";
      div.appendChild(h2);

      var table = document.createElement('table');
      table.id = 'group-keys-table';
      table.style.borderCollapse = "collapse";
      table.setAttribute("class", "crypto");
      table.setAttribute('cellpadding', 3);
      table.setAttribute('cellspacing', 1);
      table.setAttribute('border', 1);
      table.setAttribute('width', "80%");
      div.appendChild(table);
    }
  }
}
// ----------------------------------------------------------
//Encrypt button is added in the upper left corner


function tryAddEncryptButton(update) {

  // Check if it already exists.
  if (document.getElementById('encrypt-button')) {
    return;
  }

  var encryptWrapper = document.createElement("span");
  encryptWrapper.style.float = "left";


  var encryptLabel = document.createElement("label");
  encryptLabel.setAttribute("class", "submitBtn uiButton uiButtonConfirm");

  var encryptButton = document.createElement("input");
  encryptButton.setAttribute("value", "Encrypt");
  encryptButton.setAttribute("type", "button");
  encryptButton.setAttribute("id", "encrypt-button");
  encryptButton.setAttribute("class", "encrypt-button");
  encryptButton.addEventListener("click", DoEncrypt, false);

  encryptLabel.appendChild(encryptButton);
  encryptWrapper.appendChild(encryptLabel);

  var liParent;
  try {
    liParent = document.getElementsByName("xhpc_message")[0].parentNode;
  } catch(e) {
    return;
  }
  liParent.appendChild(encryptWrapper);

  decryptTextOfChildNodes(document);
  decryptTextOfChildNodes2(document);

}

function addEncryptCommentButton(e) {

  var commentAreas = e.getElementsByClassName('textInput UFIAddCommentInput');

  for (var j = 0; j < commentAreas.length; j++) {

    if (commentAreas[j].parentNode.parentNode.parentNode.parentNode.getElementsByClassName("encrypt-comment-button").length > 0) {
      continue;
    }

    var encryptWrapper = document.createElement("span");
    encryptWrapper.setAttribute("class", "");
    encryptWrapper.style.cssFloat = "left";
    encryptWrapper.style.cssPadding = "2px";


    var encryptLabel = document.createElement("label");
    encryptLabel.setAttribute("class", "submitBtn uiButton uiButtonConfirm crypto");

    var encryptButton = document.createElement("input");
    encryptButton.setAttribute("value", "Encrypt");
    encryptButton.setAttribute("type", "button");
    encryptButton.setAttribute("class", "encrypt-comment-button crypto");
    encryptButton.addEventListener("click", DoEncrypt, false);

    encryptLabel.appendChild(encryptButton);
    encryptWrapper.appendChild(encryptLabel);

    commentAreas[j].parentNode.parentNode.parentNode.parentNode.appendChild(encryptWrapper);
  }
}

function AddElements() {
  if (document.URL.match(/groups/)) {
    tryAddEncryptButton();
    addEncryptCommentButton(document);
  }
  AddEncryptionTab()
}

function GenerateKeyWrapper() {
  var grp = document.getElementById('gen-key-group').value;
  if (grp.length < 1) {
    alert("You need to set a group");
    return;
  }
  GenerateKey(grp);
  var k = keys[grp];
  UpdateKeysTable();
}

function UpdateKeysTable() {
  var table = document.getElementById('group-keys-table');
  if (!table) return;
  table.innerHTML = '';

  // ugly due to events + GreaseMonkey.
  // header
  var row = document.createElement('tr');
  var th = document.createElement('th');
  th.innerHTML = "Group";
  row.appendChild(th);
  th = document.createElement('th');
  th.innerHTML = "Key";
  row.appendChild(th);
  th = document.createElement('th');
  th.innerHTML = "&nbsp;";
  row.appendChild(th);
  table.appendChild(row);

  // keys
  for (var group in keys) {
    var row = document.createElement('tr');
    row.setAttribute("data-group", group);
    var td = document.createElement('td');
    td.innerHTML = group;
    row.appendChild(td);
    td = document.createElement('td');
    td.innerHTML = keys[group];
    row.appendChild(td);
    td = document.createElement('td');

    var button = document.createElement('input');
    button.type = 'button';
    button.value = 'Delete';
    button.addEventListener("click", function(event) {
      DeleteKey(event.target.parentNode.parentNode);
    }, false);
    td.appendChild(button);
    row.appendChild(td);

    table.appendChild(row);
  }

  // add friend line
  row = document.createElement('tr');

  var td = document.createElement('td');
  td.innerHTML = '<input id="new-key-group" type="text" size="8">';
  row.appendChild(td);

  td = document.createElement('td');
  td.innerHTML = '<input id="new-key-key" type="text" size="24">';
  row.appendChild(td);

  td = document.createElement('td');
  button = document.createElement('input');
  button.type = 'button';
  button.value = 'Add Key';
  button.addEventListener("click", AddKey, false);
  td.appendChild(button);
  row.appendChild(td);

  table.appendChild(row);

  // generate line
  row = document.createElement('tr');

  td = document.createElement('td');
  td.innerHTML = '<input id="gen-key-group" type="text" size="8">';
  row.appendChild(td);

  table.appendChild(row);

  td = document.createElement('td');
  td.colSpan = "2";
  button = document.createElement('input');
  button.type = 'button';
  button.value = 'Generate Key';
  button.addEventListener("click", GenerateKeyWrapper, false);
  td.appendChild(button);
  row.appendChild(td);
}

function AddKey() {
  var g = document.getElementById('new-key-group').value;
  if (g.length < 1) {
    alert("You need to set a group");
    return;
  }
  var k = document.getElementById('new-key-key').value;
  keys[g] = k;
  SaveKeys();
  UpdateKeysTable();
}

function DeleteKey(e) {
  var group = e.getAttribute("data-group");
  delete keys[group];
  SaveKeys();
  UpdateKeysTable();
}

function DoEncrypt(e) {
  // triggered by the encrypt button
  // Contents of post or comment are saved to dummy node. So updation of contens of dummy node is also required after encryption
  if (e.target.className == "encrypt-button") {
    var textHolder = document.getElementsByClassName("uiTextareaAutogrow input mentionsTextarea textInput")[0];
    var dummy = document.getElementsByName("xhpc_message")[0];
  } else {
    console.log(e.target);
    var dummy = e.target.parentNode.parentNode.parentNode.parentNode.parentNode.parentNode.getElementsByClassName("mentionsHidden")[0];
    var textHolder = e.target.parentNode.parentNode.parentNode.parentNode.getElementsByClassName("textInput mentionsTextarea")[0];
  }

  //Get the plain text
  //var vntext=textHolder.value;
  var vntext = dummy.value;

  //Ecrypt
  var vn2text = Encrypt(vntext, CurrentGroup());

  //Replace with encrypted text
  textHolder.value = vn2text;
  dummy.value = vn2text;

  textHolder.select();

}

// Currently results in a TypeError if we're not on a group page.
function CurrentGroup() {
  // Try a few DOM elements that might exist, and would contain the group name.
  var domElement = document.getElementById('groupsJumpTitle')|| document.getElementsByClassName('uiButtonText');
  var groupName = domElement.textContent;
  return groupName;
}

function GetMsgText(msg) {
  return msg.innerHTML;
}

function getTextFromChildren(parent, skipClass, results) {
  var children = parent.childNodes,
    item;
  var re = new RegExp("\\b" + skipClass + "\\b");
  for (var i = 0, len = children.length; i < len; i++) {
    item = children[i];
    // if text node, collect it's text
    if (item.nodeType == 3) {
      results.push(item.nodeValue);
    } else if (!item.className || !item.className.match(re)) {
      // if it has a className and it doesn't match
      // what we're skipping, then recurse on it
      getTextFromChildren(item, skipClass, results);
    }
  }
}

function GetMsgTextForDecryption(msg) {
  try {
    var visibleDiv = msg.getElementsByClassName("UFICommentBody");
    if (visibleDiv.length) {
      var visibleDiv = document.getElementsByClassName("UFICommentBody");
      var text = [];
      getTextFromChildren(visibleDiv[0], "text_exposed_hide", text);
      var mg = text.join("");
      return mg;

    } else {
      var innerText = msg.textContent;

      // Get rid of the trailing newline, if there is one.
      if (innerText[innerText.length-1] === '\n') {
        innerText = innerText.slice(0, innerText.length-1);
      }

      return innerText;
    }

  } catch(err) {
    return msg.innerText;
  }
}

function wbr(str, num) {
    return str.replace(RegExp("(.{" + num + "})(.)", "g"), function(all, text, char) {
    return text + "<wbr>" + char;
  });
}

function SetMsgText(msg, new_text) {
  msg.innerHTML = new_text;
}

// Rudimentary attack against HTML/JAvascript injection. From mustache.js. https://github.com/janl/mustache.js/blob/master/mustache.js#L53
function escapeHtml(string) {

  var entityMap = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': '&quot;',
    "'": '&#39;',
    "/": '&#x2F;'
  };

  return String(string).replace(/[&<>"'\/]/g, function (s) {
    return entityMap[s];
  });
}

function DecryptMsg(msg) {
  // we mark the box with the class "decrypted" to prevent attempting to decrypt it multiple times.
  if (!/decrypted/.test(msg.className)) {
    var txt = GetMsgTextForDecryption(msg);
	var displayHTML;
    try {
      var group = CurrentGroup();
      var decryptedMsg = Decrypt(txt, group);
      decryptedMsg = escapeHtml(decryptedMsg);
      displayHTML = '<font color="#00AA00">Decrypted message: ' + decryptedMsg + '</font><br><hr>' + txt;
    }
    catch (e) {
      displayHTML = '<font color="#FF88">Could not decrypt (' + e + ').</font><br><hr>' + txt;
    }

    SetMsgText(msg, displayHTML);
    msg.className += " decrypted";
  }
}


/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////
//
// Below here is from other libraries. Here be dragons.
//
/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////


/** @fileOverview Javascript cryptography implementation.
*
* Crush to remove comments, shorten variable names and
* generally reduce transmission size.
*
* @author Emily Stark
* @author Mike Hamburg
* @author Dan Boneh
*/

"use strict"; /*jslint indent: 2, bitwise: false, nomen: false, plusplus: false, white: false, regexp: false */
/*global document, window, escape, unescape */

/** @namespace The Stanford Javascript Crypto Library, top-level namespace. */
var sjcl = { /** @namespace Symmetric ciphers. */
  cipher: {},

  /** @namespace Hash functions. Right now only SHA256 is implemented. */
  hash: {},

  /** @namespace Block cipher modes of operation. */
  mode: {},

  /** @namespace Miscellaneous. HMAC and PBKDF2. */
  misc: {},

  /**
* @namespace Bit array encoders and decoders.
*
* @description
* The members of this namespace are functions which translate between
* SJCL's bitArrays and other objects (usually strings). Because it
* isn't always clear which direction is encoding and which is decoding,
* the method names are "fromBits" and "toBits".
*/
  codec: {},

  /** @namespace Exceptions. */
  exception: { /** @class Ciphertext is corrupt. */
    corrupt: function(message) {
      this.toString = function() {
        return "CORRUPT: " + this.message;
      };
      this.message = message;
    },

    /** @class Invalid parameter. */
    invalid: function(message) {
      this.toString = function() {
        return "INVALID: " + this.message;
      };
      this.message = message;
    },

    /** @class Bug or missing feature in SJCL. */
    bug: function(message) {
      this.toString = function() {
        return "BUG: " + this.message;
      };
      this.message = message;
    },

    // Added by mbarrien to fix an SJCL bug.
    /** @class Not ready to encrypt. */
    notready: function(message) {
      this.toString = function() {
        return "NOTREADY: " + this.message;
      };
      this.message = message;
    }
  }
};

/** @fileOverview Low-level AES implementation.
*
* This file contains a low-level implementation of AES, optimized for
* size and for efficiency on several browsers. It is based on
* OpenSSL's aes_core.c, a public-domain implementation by Vincent
* Rijmen, Antoon Bosselaers and Paulo Barreto.
*
* An older version of this implementation is available in the public
* domain, but this one is (c) Emily Stark, Mike Hamburg, Dan Boneh,
* Stanford University 2008-2010 and BSD-licensed for liability
* reasons.
*
* @author Emily Stark
* @author Mike Hamburg
* @author Dan Boneh
*/

/**
* Schedule out an AES key for both encryption and decryption. This
* is a low-level class. Use a cipher mode to do bulk encryption.
*
* @constructor
* @param {Array} key The key as an array of 4, 6 or 8 words.
*
* @class Advanced Encryption Standard (low-level interface)
*/
sjcl.cipher.aes = function(key) {
  if (!this._tables[0][0][0]) {
    this._precompute();
  }

  var i, j, tmp, encKey, decKey, sbox = this._tables[0][4],
    decTable = this._tables[1],
    keyLen = key.length,
    rcon = 1;

  if (keyLen !== 4 && keyLen !== 6 && keyLen !== 8) {
    throw new sjcl.exception.invalid("invalid aes key size");
  }

  this._key = [encKey = key.slice(0), decKey = []];

  // schedule encryption keys
  for (i = keyLen; i < 4 * keyLen + 28; i++) {
    tmp = encKey[i - 1];

    // apply sbox
    if (i % keyLen === 0 || (keyLen === 8 && i % keyLen === 4)) {
      tmp = sbox[tmp >>> 24] << 24 ^ sbox[tmp >> 16 & 255] << 16 ^ sbox[tmp >> 8 & 255] << 8 ^ sbox[tmp & 255];

      // shift rows and add rcon
      if (i % keyLen === 0) {
        tmp = tmp << 8 ^ tmp >>> 24 ^ rcon << 24;
        rcon = rcon << 1 ^ (rcon >> 7) * 283;
      }
    }

    encKey[i] = encKey[i - keyLen] ^ tmp;
  }

  // schedule decryption keys
  for (j = 0; i; j++, i--) {
    tmp = encKey[j & 3 ? i : i - 4];
    if (i <= 4 || j < 4) {
      decKey[j] = tmp;
    } else {
      decKey[j] = decTable[0][sbox[tmp >>> 24]] ^ decTable[1][sbox[tmp >> 16 & 255]] ^ decTable[2][sbox[tmp >> 8 & 255]] ^ decTable[3][sbox[tmp & 255]];
    }
  }
};

sjcl.cipher.aes.prototype = {
  // public
  /* Something like this might appear here eventually
name: "AES",
blockSize: 4,
keySizes: [4,6,8],
*/

  /**
* Encrypt an array of 4 big-endian words.
* @param {Array} data The plaintext.
* @return {Array} The ciphertext.
*/
  encrypt: function(data) {
    return this._crypt(data, 0);
  },

  /**
* Decrypt an array of 4 big-endian words.
* @param {Array} data The ciphertext.
* @return {Array} The plaintext.
*/
  decrypt: function(data) {
    return this._crypt(data, 1);
  },

  /**
* The expanded S-box and inverse S-box tables. These will be computed
* on the client so that we don't have to send them down the wire.
*
* There are two tables, _tables[0] is for encryption and
* _tables[1] is for decryption.
*
* The first 4 sub-tables are the expanded S-box with MixColumns. The
* last (_tables[01][4]) is the S-box itself.
*
* @private
*/
  _tables: [
    [
      [],
      [],
      [],
      [],
      []
    ],
    [
      [],
      [],
      [],
      [],
      []
    ]
  ],

  /**
* Expand the S-box tables.
*
* @private
*/
  _precompute: function() {
    var encTable = this._tables[0],
      decTable = this._tables[1],
      sbox = encTable[4],
      sboxInv = decTable[4],
      i, x, xInv, d = [],
      th = [],
      x2, x4, x8, s, tEnc, tDec;

    // Compute double and third tables
    for (i = 0; i < 256; i++) {
      th[(d[i] = i << 1 ^ (i >> 7) * 283) ^ i] = i;
    }

    for (x = xInv = 0; !sbox[x]; x ^= x2 || 1, xInv = th[xInv] || 1) {
      // Compute sbox
      s = xInv ^ xInv << 1 ^ xInv << 2 ^ xInv << 3 ^ xInv << 4;
      s = s >> 8 ^ s & 255 ^ 99;
      sbox[x] = s;
      sboxInv[s] = x;

      // Compute MixColumns
      x8 = d[x4 = d[x2 = d[x]]];
      tDec = x8 * 0x1010101 ^ x4 * 0x10001 ^ x2 * 0x101 ^ x * 0x1010100;
      tEnc = d[s] * 0x101 ^ s * 0x1010100;

      for (i = 0; i < 4; i++) {
        encTable[i][x] = tEnc = tEnc << 24 ^ tEnc >>> 8;
        decTable[i][s] = tDec = tDec << 24 ^ tDec >>> 8;
      }
    }

    // Compactify. Considerable speedup on Firefox.
    for (i = 0; i < 5; i++) {
      encTable[i] = encTable[i].slice(0);
      decTable[i] = decTable[i].slice(0);
    }
  },

  /**
* Encryption and decryption core.
* @param {Array} input Four words to be encrypted or decrypted.
* @param dir The direction, 0 for encrypt and 1 for decrypt.
* @return {Array} The four encrypted or decrypted words.
* @private
*/
  _crypt: function(input, dir) {
    if (input.length !== 4) {
      throw new sjcl.exception.invalid("invalid aes block size");
    }

    var key = this._key[dir],
      // state variables a,b,c,d are loaded with pre-whitened data
      a = input[0] ^ key[0],
      b = input[dir ? 3 : 1] ^ key[1],
      c = input[2] ^ key[2],
      d = input[dir ? 1 : 3] ^ key[3],
      a2, b2, c2,

      nInnerRounds = key.length / 4 - 2,
      i, kIndex = 4,
      out = [0, 0, 0, 0],
      table = this._tables[dir],

      // load up the tables
      t0 = table[0],
      t1 = table[1],
      t2 = table[2],
      t3 = table[3],
      sbox = table[4];

    // Inner rounds. Cribbed from OpenSSL.
    for (i = 0; i < nInnerRounds; i++) {
      a2 = t0[a >>> 24] ^ t1[b >> 16 & 255] ^ t2[c >> 8 & 255] ^ t3[d & 255] ^ key[kIndex];
      b2 = t0[b >>> 24] ^ t1[c >> 16 & 255] ^ t2[d >> 8 & 255] ^ t3[a & 255] ^ key[kIndex + 1];
      c2 = t0[c >>> 24] ^ t1[d >> 16 & 255] ^ t2[a >> 8 & 255] ^ t3[b & 255] ^ key[kIndex + 2];
      d = t0[d >>> 24] ^ t1[a >> 16 & 255] ^ t2[b >> 8 & 255] ^ t3[c & 255] ^ key[kIndex + 3];
      kIndex += 4;
      a = a2;
      b = b2;
      c = c2;
    }

    // Last round.
    for (i = 0; i < 4; i++) {
      out[dir ? 3 & -i : i] = sbox[a >>> 24] << 24 ^ sbox[b >> 16 & 255] << 16 ^ sbox[c >> 8 & 255] << 8 ^ sbox[d & 255] ^ key[kIndex++];
      a2 = a;
      a = b;
      b = c;
      c = d;
      d = a2;
    }
    return out;
  }
};

/** @fileOverview Arrays of bits, encoded as arrays of Numbers.
*
* @author Emily Stark
* @author Mike Hamburg
* @author Dan Boneh
*/

/** @namespace Arrays of bits, encoded as arrays of Numbers.
*
* @description
* <p>
* These objects are the currency accepted by SJCL's crypto functions.
* </p>
*
* <p>
* Most of our crypto primitives operate on arrays of 4-byte words internally,
* but many of them can take arguments that are not a multiple of 4 bytes.
* This library encodes arrays of bits (whose size need not be a multiple of 8
* bits) as arrays of 32-bit words. The bits are packed, big-endian, into an
* array of words, 32 bits at a time. Since the words are double-precision
* floating point numbers, they fit some extra data. We use this (in a private,
* possibly-changing manner) to encode the number of bits actually present
* in the last word of the array.
* </p>
*
* <p>
* Because bitwise ops clear this out-of-band data, these arrays can be passed
* to ciphers like AES which want arrays of words.
* </p>
*/
sjcl.bitArray = {
  /**
* Array slices in units of bits.
* @param {bitArray a} The array to slice.
* @param {Number} bstart The offset to the start of the slice, in bits.
* @param {Number} bend The offset to the end of the slice, in bits. If this is undefined,
* slice until the end of the array.
* @return {bitArray} The requested slice.
*/
  bitSlice: function(a, bstart, bend) {
    a = sjcl.bitArray._shiftRight(a.slice(bstart / 32), 32 - (bstart & 31)).slice(1);
    return(bend === undefined) ? a : sjcl.bitArray.clamp(a, bend - bstart);
  },

  /**
* Concatenate two bit arrays.
* @param {bitArray} a1 The first array.
* @param {bitArray} a2 The second array.
* @return {bitArray} The concatenation of a1 and a2.
*/
  concat: function(a1, a2) {
    if (a1.length === 0 || a2.length === 0) {
      return a1.concat(a2);
    }

    var out, i, last = a1[a1.length - 1],
      shift = sjcl.bitArray.getPartial(last);
    if (shift === 32) {
      return a1.concat(a2);
    } else {
      return sjcl.bitArray._shiftRight(a2, shift, last | 0, a1.slice(0, a1.length - 1));
    }
  },

  /**
* Find the length of an array of bits.
* @param {bitArray} a The array.
* @return {Number} The length of a, in bits.
*/
  bitLength: function(a) {
    var l = a.length,
      x;
    if (l === 0) {
      return 0;
    }
    x = a[l - 1];
    return(l - 1) * 32 + sjcl.bitArray.getPartial(x);
  },

  /**
* Truncate an array.
* @param {bitArray} a The array.
* @param {Number} len The length to truncate to, in bits.
* @return {bitArray} A new array, truncated to len bits.
*/
  clamp: function(a, len) {
    if (a.length * 32 < len) {
      return a;
    }
    a = a.slice(0, Math.ceil(len / 32));
    var l = a.length;
    len = len & 31;
    if (l > 0 && len) {
      a[l - 1] = sjcl.bitArray.partial(len, a[l - 1] & 0x80000000 >> (len - 1), 1);
    }
    return a;
  },

  /**
* Make a partial word for a bit array.
* @param {Number} len The number of bits in the word.
* @param {Number} x The bits.
* @param {Number} [0] _end Pass 1 if x has already been shifted to the high side.
* @return {Number} The partial word.
*/
  partial: function(len, x, _end) {
    if (len === 32) {
      return x;
    }
    return(_end ? x | 0 : x << (32 - len)) + len * 0x10000000000;
  },

  /**
* Get the number of bits used by a partial word.
* @param {Number} x The partial word.
* @return {Number} The number of bits used by the partial word.
*/
  getPartial: function(x) {
    return Math.round(x / 0x10000000000) || 32;
  },

  /**
* Compare two arrays for equality in a predictable amount of time.
* @param {bitArray} a The first array.
* @param {bitArray} b The second array.
* @return {boolean} true if a == b; false otherwise.
*/
  equal: function(a, b) {
    if (sjcl.bitArray.bitLength(a) !== sjcl.bitArray.bitLength(b)) {
      return false;
    }
    var x = 0,
      i;
    for (i = 0; i < a.length; i++) {
      x |= a[i] ^ b[i];
    }
    return(x === 0);
  },

  /** Shift an array right.
* @param {bitArray} a The array to shift.
* @param {Number} shift The number of bits to shift.
* @param {Number} [carry=0] A byte to carry in
* @param {bitArray} [out=[]] An array to prepend to the output.
* @private
*/
  _shiftRight: function(a, shift, carry, out) {
    var i, last2 = 0,
      shift2;
    if (out === undefined) {
      out = [];
    }

    for (; shift >= 32; shift -= 32) {
      out.push(carry);
      carry = 0;
    }
    if (shift === 0) {
      return out.concat(a);
    }

    for (i = 0; i < a.length; i++) {
      out.push(carry | a[i] >>> shift);
      carry = a[i] << (32 - shift);
    }
    last2 = a.length ? a[a.length - 1] : 0;
    shift2 = sjcl.bitArray.getPartial(last2);
    out.push(sjcl.bitArray.partial(shift + shift2 & 31, (shift + shift2 > 32) ? carry : out.pop(), 1));
    return out;
  },

  /** xor a block of 4 words together.
* @private
*/
  _xor4: function(x, y) {
    return [x[0] ^ y[0], x[1] ^ y[1], x[2] ^ y[2], x[3] ^ y[3]];
  }
};

/** @fileOverview Bit array codec implementations.
*
* @author Emily Stark
* @author Mike Hamburg
* @author Dan Boneh
*/

/** @namespace Base64 encoding/decoding */
sjcl.codec.base64 = {
  /** The base64 alphabet.
* @private
*/
  _chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
  
  /** Convert from a bitArray to a base64 string. */
  fromBits: function (arr, _noEquals, _url) {
    var out = "", i, bits=0, c = sjcl.codec.base64._chars, ta=0, bl = sjcl.bitArray.bitLength(arr);
    if (_url) c = c.substr(0,62) + '-_';
    for (i=0; out.length * 6 < bl; ) {
      out += c.charAt((ta ^ arr[i]>>>bits) >>> 26);
      if (bits < 6) {
        ta = arr[i] << (6-bits);
        bits += 26;
        i++;
      } else {
        ta <<= 6;
        bits -= 6;
      }
    }
    while ((out.length & 3) && !_noEquals) { out += "="; }
    return out;
  },
  
  /** Convert from a base64 string to a bitArray */
  toBits: function(str, _url) {
    str = str.replace(/\s|=/g,'');
    var out = [], i, bits=0, c = sjcl.codec.base64._chars, ta=0, x;
    if (_url) c = c.substr(0,62) + '-_';
    for (i=0; i<str.length; i++) {
      x = c.indexOf(str.charAt(i));
      if (x < 0) {
        throw new sjcl.exception.invalid("this isn't base64!");
      }
      if (bits > 26) {
        bits -= 26;
        out.push(ta ^ x>>>bits);
        ta = x << (32-bits);
      } else {
        bits += 6;
        ta ^= x << (32-bits);
      }
    }
    if (bits&56) {
      out.push(sjcl.bitArray.partial(bits&56, ta, 1));
    }
    return out;
  }
};

sjcl.codec.base64url = {
  fromBits: function (arr) { return sjcl.codec.base64.fromBits(arr,1,1); },
  toBits: function (str) { return sjcl.codec.base64.toBits(str,1); }
};


/** @fileOverview Bit array codec implementations.
*
* @author Emily Stark
* @author Mike Hamburg
* @author Dan Boneh
*/

/** @namespace UTF-8 strings */
sjcl.codec.utf8String = { /** Convert from a bitArray to a UTF-8 string. */
  fromBits: function (arr) {
    return decodeURIComponent(escape(sjcl.codec.utf8String.fromBits_noURI(arr)));
  },

  fromBits_noURI: function(arr) {
    var out = "",
      bl = sjcl.bitArray.bitLength(arr),
      i, tmp;
    for (i = 0; i < bl / 8; i++) {
      if ((i & 3) === 0) {
        tmp = arr[i / 4];
      }
      out += String.fromCharCode(tmp >>> 24);
      tmp <<= 8;
    }
    return out;
  },

  /** Convert from a UTF-8 string to a bitArray. */
  toBits: function(str) {
    str = unescape(encodeURIComponent(str));
    var out = [],
      i, tmp = 0;
    for (i = 0; i < str.length; i++) {
      tmp = tmp << 8 | str.charCodeAt(i);
      if ((i & 3) === 3) {
        out.push(tmp);
        tmp = 0;
      }
    }
    if (i & 3) {
      out.push(sjcl.bitArray.partial(8 * (i & 3), tmp));
    }
    return out;
  }
};

/** @fileOverview Password-based key-derivation function, version 2.0.
*
* @author Emily Stark
* @author Mike Hamburg
* @author Dan Boneh
*/

/** Password-Based Key-Derivation Function, version 2.0.
*
* Generate keys from passwords using PBKDF2-HMAC-SHA256.
*
* This is the method specified by RSA's PKCS #5 standard.
*
* @param {bitArray|String} password The password.
* @param {bitArray} salt The salt. Should have lots of entropy.
* @param {Number} [count=1000] The number of iterations. Higher numbers make the function slower but more secure.
* @param {Number} [length] The length of the derived key. Defaults to the
output size of the hash function.
* @param {Object} [Prff=sjcl.misc.hmac] The pseudorandom function family.
* @return {bitArray} the derived key.
*/
sjcl.misc.pbkdf2 = function (password, salt, count, length, Prff) {
  count = count || 1000;
  
  if (length < 0 || count < 0) {
    throw sjcl.exception.invalid("invalid params to pbkdf2");
  }
  
  if (typeof password === "string") {
    password = sjcl.codec.utf8String.toBits(password);
  }
  
  Prff = Prff || sjcl.misc.hmac;
  
  var prf = new Prff(password),
      u, ui, i, j, k, out = [], b = sjcl.bitArray;

  for (k = 1; 32 * out.length < (length || 1); k++) {
    u = ui = prf.encrypt(b.concat(salt,[k]));
    
    for (i=1; i<count; i++) {
      ui = prf.encrypt(ui);
      for (j=0; j<ui.length; j++) {
        u[j] ^= ui[j];
      }
    }
    
    out = out.concat(u);
  }

  if (length) { out = b.clamp(out, length); }

  return out;
};

/** @fileOverview HMAC implementation.
*
* @author Emily Stark
* @author Mike Hamburg
* @author Dan Boneh
*/

/** HMAC with the specified hash function.
* @constructor
* @param {bitArray} key the key for HMAC.
* @param {Object} [hash=sjcl.hash.sha256] The hash function to use.
*/

// These functions are obfuscated for CS255, since you will be implementing HMAC yourself.
sjcl.misc.hmac=function(a,b){
  this.M=b=b||sjcl.hash.sha256;var c=[[],[]],d=b.prototype.blockSize/32;
  this.l=[new b,new b];if(a.length>d)a=b.hash(a);
  for(b=0;b<d;b++){c[0][b]=a[b]^0x36363636;c[1][b]=a[b]^0x5C5C5C5C}
  this.l[0].update(c[0]);this.l[1].update(c[1]);
};
sjcl.misc.hmac.prototype.encrypt=sjcl.misc.hmac.prototype.mac=function(a,b){
  a=(new this.M(this.l[0])).update(a,b).finalize();
  return(new this.M(this.l[1])).update(a).finalize()
};

/** @fileOverview Javascript SHA-256 implementation.
*
* An older version of this implementation is available in the public
* domain, but this one is (c) Emily Stark, Mike Hamburg, Dan Boneh,
* Stanford University 2008-2010 and BSD-licensed for liability
* reasons.
*
* Special thanks to Aldo Cortesi for pointing out several bugs in
* this code.
*
* @author Emily Stark
* @author Mike Hamburg
* @author Dan Boneh
*/

/**
* Context for a SHA-256 operation in progress.
* @constructor
* @class Secure Hash Algorithm, 256 bits.
*/
sjcl.hash.sha256 = function (hash) {
  if (!this._key[0]) { this._precompute(); }
  if (hash) {
    this._h = hash._h.slice(0);
    this._buffer = hash._buffer.slice(0);
    this._length = hash._length;
  } else {
    this.reset();
  }
};

/**
* Hash a string or an array of words.
* @static
* @param {bitArray|String} data the data to hash.
* @return {bitArray} The hash value, an array of 16 big-endian words.
*/
sjcl.hash.sha256.hash = function (data) {
  return (new sjcl.hash.sha256()).update(data).finalize();
};

sjcl.hash.sha256.prototype = {
  /**
* The hash's block size, in bits.
* @constant
*/
  blockSize: 512,
   
  /**
* Reset the hash state.
* @return this
*/
  reset:function () {
    this._h = this._init.slice(0);
    this._buffer = [];
    this._length = 0;
    return this;
  },
  
  /**
* Input several words to the hash.
* @param {bitArray|String} data the data to hash.
* @return this
*/
  update: function (data) {
    if (typeof data === "string") {
      data = sjcl.codec.utf8String.toBits(data);
    }
    var i, b = this._buffer = sjcl.bitArray.concat(this._buffer, data),
        ol = this._length,
        nl = this._length = ol + sjcl.bitArray.bitLength(data);
    for (i = 512+ol & -512; i <= nl; i+= 512) {
      this._block(b.splice(0,16));
    }
    return this;
  },
  
  /**
* Complete hashing and output the hash value.
* @return {bitArray} The hash value, an array of 8 big-endian words.
*/
  finalize:function () {
    var i, b = this._buffer, h = this._h;

    // Round out and push the buffer
    b = sjcl.bitArray.concat(b, [sjcl.bitArray.partial(1,1)]);
    
    // Round out the buffer to a multiple of 16 words, less the 2 length words.
    for (i = b.length + 2; i & 15; i++) {
      b.push(0);
    }
    
    // append the length
    b.push(Math.floor(this._length / 0x100000000));
    b.push(this._length | 0);

    while (b.length) {
      this._block(b.splice(0,16));
    }

    this.reset();
    return h;
  },

  /**
* The SHA-256 initialization vector, to be precomputed.
* @private
*/
  _init:[],
  /*
_init:[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],
*/
  
  /**
* The SHA-256 hash key, to be precomputed.
* @private
*/
  _key:[],
  /*
_key:
[0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2],
*/


  /**
* Function to precompute _init and _key.
* @private
*/
  _precompute: function () {
    var i = 0, prime = 2, factor;

    function frac(x) { return (x-Math.floor(x)) * 0x100000000 | 0; }

    outer: for (; i<64; prime++) {
      for (factor=2; factor*factor <= prime; factor++) {
        if (prime % factor === 0) {
          // not a prime
          continue outer;
        }
      }
      
      if (i<8) {
        this._init[i] = frac(Math.pow(prime, 1/2));
      }
      this._key[i] = frac(Math.pow(prime, 1/3));
      i++;
    }
  },
  
  /**
* Perform one cycle of SHA-256.
* @param {bitArray} words one block of words.
* @private
*/
  _block:function (words) {
    var i, tmp, a, b,
      w = words.slice(0),
      h = this._h,
      k = this._key,
      h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3],
      h4 = h[4], h5 = h[5], h6 = h[6], h7 = h[7];

    /* Rationale for placement of |0 :
* If a value can overflow is original 32 bits by a factor of more than a few
* million (2^23 ish), there is a possibility that it might overflow the
* 53-bit mantissa and lose precision.
*
* To avoid this, we clamp back to 32 bits by |'ing with 0 on any value that
* propagates around the loop, and on the hash state h[]. I don't believe
* that the clamps on h4 and on h0 are strictly necessary, but it's close
* (for h4 anyway), and better safe than sorry.
*
* The clamps on h[] are necessary for the output to be correct even in the
* common case and for short inputs.
*/
    for (i=0; i<64; i++) {
      // load up the input word for this round
      if (i<16) {
        tmp = w[i];
      } else {
        a = w[(i+1 ) & 15];
        b = w[(i+14) & 15];
        tmp = w[i&15] = ((a>>>7 ^ a>>>18 ^ a>>>3 ^ a<<25 ^ a<<14) +
                         (b>>>17 ^ b>>>19 ^ b>>>10 ^ b<<15 ^ b<<13) +
                         w[i&15] + w[(i+9) & 15]) | 0;
      }
      
      tmp = (tmp + h7 + (h4>>>6 ^ h4>>>11 ^ h4>>>25 ^ h4<<26 ^ h4<<21 ^ h4<<7) + (h6 ^ h4&(h5^h6)) + k[i]); // | 0;
      
      // shift register
      h7 = h6; h6 = h5; h5 = h4;
      h4 = h3 + tmp | 0;
      h3 = h2; h2 = h1; h1 = h0;

      h0 = (tmp + ((h1&h2) ^ (h3&(h1^h2))) + (h1>>>2 ^ h1>>>13 ^ h1>>>22 ^ h1<<30 ^ h1<<19 ^ h1<<10)) | 0;
    }

    h[0] = h[0]+h0 | 0;
    h[1] = h[1]+h1 | 0;
    h[2] = h[2]+h2 | 0;
    h[3] = h[3]+h3 | 0;
    h[4] = h[4]+h4 | 0;
    h[5] = h[5]+h5 | 0;
    h[6] = h[6]+h6 | 0;
    h[7] = h[7]+h7 | 0;
  }
};

// If we are running in phantom
if (typeof phantom !== "undefined") {
  console.log("You are running in PhantomJS. We are running the test suite. Clearing local storage.");
  localStorage.clear();
}

// This is the initialization
SetupUsernames();
LoadKeys();
AddElements();
UpdateKeysTable();
RegisterChangeEvents();

console.log("CS255 script finished loading.");

if (typeof phantom !== "undefined") {
  console.log("Hello! You're running in phantom.js.");
  _TestFramework();
  phantom.exit();
}