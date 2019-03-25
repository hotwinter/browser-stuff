function foo(x, cb) {
    var a = x.a;
    cb(a);
    return x.b;
}

var o = {a: 0.1, b: 0.2};
var c = new ArrayBuffer(0x100);
for(var i = 0; i < 100000; i++) {
    foo(o, function(a) { return a + 1; });
}
console.log(foo(o, function(a) { o.b = c; }));
