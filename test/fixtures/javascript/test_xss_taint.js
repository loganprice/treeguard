function handleRequest(req, res) {
    const userInput = req.query.get('name');
    const htmlOutput = "<h1>Hello " + userInput + "</h1>";
    // ruleid: js-xss-taint
    res.send(htmlOutput);
}

function handleSanitizedRequest(req, res) {
    const userInput = req.query.get('name');
    const cleanInput = escapeHTML(userInput);
    // ok: js-xss-taint
    res.send(cleanInput);
}
