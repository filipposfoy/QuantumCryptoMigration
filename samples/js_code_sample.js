const crypto = require('crypto');

function md5_vulnerability() {
    const password = "SensitivePassword";
    const hash = crypto.createHash('md5').update(password).digest('hex');

    console.log("Weak Hashed Password (MD5):", hash);
}

md5_vulnerability();
