async function encrypt() {
    const message = document.getElementById("message").value;
    const key = document.getElementById("key").value;

    const response = await fetch('/encrypt', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ message, key })
    });

    const data = await response.json();
    document.getElementById("output").innerText =
        "Encrypted Text:\n" + data.encrypted + "\n\nKey Used:\n" + data.used_key;
}

async function decrypt() {
    const encrypted = document.getElementById("message").value;
    const key = document.getElementById("key").value;

    const response = await fetch('/decrypt', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ encrypted, key })
    });

    const data = await response.json();
    document.getElementById("output").innerText =
        "Decrypted Text:\n" + data.decrypted;
}
