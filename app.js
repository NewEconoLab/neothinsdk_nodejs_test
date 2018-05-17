var thinNeo = require("nel-neo-thinsdk");

var express = require('express');
var app = express();

//NEO thinSDK RESTful API
app.get('/addr2pksh/:addr', function (req, res) {
    var input = req.params.addr;
    var output = {
        addr:input,
        pksh:addr2pksh(input)
    }
    res.end(JSON.stringify(output))
  });
app.get('/pksh2addr/:pksh', function (req, res) {
    var input = req.params.pksh;
    var output = {
        pksh:input,
        addr:pksh2addr(input)
    }
    res.end(JSON.stringify(output))
});
  
app.listen(3000, function () {
    console.log('NEO thinSDK Test listening on port 3000!');
});

// test code

// addr2pksh('ALjSnMZidJqd18iQaoCgFun6iqWRm2cVtj');
// console.log("");
// pksh2addr("0x0b193415c6f098b02e81a3b14d0e3b08e9c3f79a");
// console.log("");
// pk2addr("02bf055764de0320c8221920d856d3d9b93dfc1dcbc759a560fd42553aa025ba5c");
// console.log("");
// test_4();
// console.log("");
// test_5();
// console.log("");
// test_6();
// console.log("");
// test_7();

function addr2pksh(addr) {
    // console.log("Cryptography");
    // var addr = "ALjSnMZidJqd18iQaoCgFun6iqWRm2cVtj";
    var uint8 = ThinNeo.Helper.GetPublicKeyScriptHash_FromAddress(addr);
    var hexstr = uint8.reverse().toHexString();
    console.log("addr=" + addr);
    console.log("hex=" + hexstr);
    return '0x' + hexstr;

}
function pksh2addr(pksh) {
    console.log("Hash2Address");
    // var hexstr = "0x0b193415c6f098b02e81a3b14d0e3b08e9c3f79a";
    var hashrev = pksh.hexToBytes();
    var hash = hashrev.reverse();
    var addr = ThinNeo.Helper.GetAddressFromScriptHash(hash);
    console.log("hex=" + pksh);
    console.log("addr=" + addr);
    return addr;
}
function pk2addr(pk) {
    console.log("Test_Pubkey2Address");

    //var pubkey = "02bf055764de0320c8221920d856d3d9b93dfc1dcbc759a560fd42553aa025ba5c";
    var bytes = pk.hexToBytes();
    var addr = ThinNeo.Helper.GetAddressFromPublicKey(bytes);
    console.log("pubkey=" + pk);
    console.log("addr=" + addr);
    return addr;
}
function test_4() {
    console.log("WifDecode");
    var wif = "L2CmHCqgeNHL1i9XFhTLzUXsdr5LGjag4d56YY98FqEi4j5d83Mv";
    var prikey = ThinNeo.Helper.GetPrivateKeyFromWIF(wif);
    var pubkey = ThinNeo.Helper.GetPublicKeyFromPrivateKey(prikey);
    var addr = ThinNeo.Helper.GetAddressFromPublicKey(pubkey);
    console.log("wif=" + wif);
    console.log("prikey=" + prikey.toHexString());
    console.log("pubkey=" + pubkey.toHexString());
    console.log("addr=" + addr);

}
function test_5() {
    console.log("Sign&Vertify");
    var wif = "L2CmHCqgeNHL1i9XFhTLzUXsdr5LGjag4d56YY98FqEi4j5d83Mv";
    var prikey = ThinNeo.Helper.GetPrivateKeyFromWIF(wif);
    var pubkey = ThinNeo.Helper.GetPublicKeyFromPrivateKey(prikey);
    var addr = ThinNeo.Helper.GetAddressFromPublicKey(pubkey);

    var signdata = "010203ff1122abcd";
    var message = signdata.hexToBytes();
    var data = ThinNeo.Helper.Sign(message, prikey);
    console.log("wif=" + wif);
    console.log("addr=" + addr);
    console.log("sign=" + data.toHexString());

    var b = ThinNeo.Helper.VerifySignature(message, data, pubkey);
    console.log("verify=" + b);
}
function test_6() {
    console.log("Nep2->Prikey");
    var nep2 = "6PYT8kA51ffcAv3bJzbfcT6Uuc32QS5wHEjneRdkPYFxZSrirVHRPEpVwN";
    var n = 16384;
    var r = 8;
    var p = 8
    ThinNeo.Helper.GetPrivateKeyFromNep2(nep2, "1", n, r, p, (info, result) => {
        console.log("info=" + info);
        var prikey = result;
        console.log("result=" + prikey.toHexString());
        var pubkey = ThinNeo.Helper.GetPublicKeyFromPrivateKey(prikey);
        var address = ThinNeo.Helper.GetAddressFromPublicKey(pubkey);
        console.log("address=" + address);

    });
}
function test_7() {
    console.log("PriKey->Nep2");
    var n = 16384;
    var r = 8;
    var p = 8;

    var prikey = "94b3335830392a3586c2d7072cfe49efc3ef048876f526cbb7061b30a2278012".hexToBytes();
    ThinNeo.Helper.GetNep2FromPrivateKey(prikey, "1", n, r, p, (info, result) => {
        console.log("info=" + info);
        console.log("result=" + result);
    });
}
	