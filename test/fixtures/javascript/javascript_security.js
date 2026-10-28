// JavaScript Test Fixtures

function testEval(userInput) {
    // ruleid: js-dangerous-eval
    eval(userInput);

    // ruleid: js-dangerous-eval
    window.eval(userInput);

    // ruleid: js-dangerous-eval
    const fn = new Function("a", "b", userInput);

    // ok: js-dangerous-eval
    console.log("eval string safely");
}

function testDomXss(element, untrustedData) {
    // ruleid: js-dom-xss-innerhtml
    element.innerHTML = untrustedData;

    // ruleid: js-dom-xss-innerhtml
    element.outerHTML = "<p>" + untrustedData + "</p>";

    // ok: js-dom-xss-innerhtml
    element.textContent = untrustedData;
}
