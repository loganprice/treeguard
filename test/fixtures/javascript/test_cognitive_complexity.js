// ruleid: js-cognitive-complexity
function complexJSHandler(arr, limit) {
    if (arr && arr.length > 0) {
        for (let i = 0; i < arr.length; i++) {
            if (arr[i] > limit) {
                while (limit < 100) {
                    if (arr[i] === limit) {
                        try {
                            limit++;
                        } catch (e) {
                            console.error(e);
                        }
                    } else {
                        limit += 2;
                    }
                }
            }
        }
    }
    return limit;
}

// ok: js-cognitive-complexity
function cleanJSHandler(x) {
    if (x > 0) {
        return x * 10;
    }
    return 0;
}
