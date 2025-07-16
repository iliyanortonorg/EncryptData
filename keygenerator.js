// Helper: Uint8Array to Base64 string
function uint8ArrayToBase64(bytes) {
  let binary = "";
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary);
}

// Helper: Base64 string to Uint8Array
function base64ToUint8Array(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Generate a random salt (16 bytes)
function generateSalt() {
  return window.crypto.getRandomValues(new Uint8Array(16));
}

async function getKeyFromPassword(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);

  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    {
      name: "AES-GCM",
      length: 256,
    },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encrypt(message, password) {
  const salt = generateSalt();
  const key = await getKeyFromPassword(password, salt);
  const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 12 bytes for AES-GCM recommended
  const enc = new TextEncoder();
  const encodedMessage = enc.encode(message);

  const encryptedBuffer = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, encodedMessage);

  // Combine salt + iv + ciphertext, all base64 encoded and joined by ':'
  return [uint8ArrayToBase64(salt), uint8ArrayToBase64(iv), uint8ArrayToBase64(new Uint8Array(encryptedBuffer))].join(
    ":"
  );
}

async function decrypt(data, password) {
  const [saltB64, ivB64, encryptedB64] = data.split(":");
  const salt = base64ToUint8Array(saltB64);
  const iv = base64ToUint8Array(ivB64);
  const encryptedBytes = base64ToUint8Array(encryptedB64);

  const key = await getKeyFromPassword(password, salt);

  const decryptedBuffer = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, encryptedBytes);

  const dec = new TextDecoder();
  return dec.decode(decryptedBuffer);
}

async function runProcess(whatToDo) {
  const password = document.querySelector("#passwordInput").value.trim();
  const message = document.querySelector("[data-Message]").value.trim();

  if (!password) return "لطفاً رمز عبور را وارد کنید.";
  if (!message) return "لطفاً متن را وارد کنید.";

  try {
    if (whatToDo === "e") {
      const encrypted = await encrypt(message, password);
      return encrypted;
    } else if (whatToDo === "d") {
      const decrypted = await decrypt(message, password);
      return decrypted;
    } else {
      return "عملیات نامعتبر";
    }
  } catch (e) {
    return "خطا: " + e.message;
  }
}

document.querySelectorAll(".perspectiveDiv").forEach((box) => {
  const inner = box.querySelector(".parallax-inner");
  const maxRotate = 15;

  function updateTransform(clientX, clientY) {
    const rect = box.getBoundingClientRect();
    const x = ((clientX - rect.left) / rect.width - 0.5) * 2;
    const y = ((clientY - rect.top) / rect.height - 0.5) * 2;

    const rotateX = y * maxRotate * -1;
    const rotateY = x * maxRotate;

    inner.style.transform = `rotateX(${rotateX}deg) rotateY(${rotateY}deg)`;
  }

  box.addEventListener("mousemove", (e) => {
    updateTransform(e.clientX, e.clientY);
  });

  box.addEventListener(
    "touchmove",
    (e) => {
      if (e.touches.length > 0) {
        updateTransform(e.touches[0].clientX, e.touches[0].clientY);
      }
    },
    { passive: true }
  );

  function resetTransform() {
    inner.style.transform = "rotateX(0deg) rotateY(0deg)";
  }

  box.addEventListener("mouseleave", resetTransform);
  box.addEventListener("touchend", resetTransform);
  box.addEventListener("touchcancel", resetTransform);
});

document.querySelectorAll("textarea").forEach((textarea) => {
  textarea.addEventListener("input", () => {
    const val = textarea.value.trim();
    if (!val) {
      textarea.style.direction = "ltr"; // اگر خالی بود پیش‌فرض چپ‌چین
      return;
    }

    // بررسی اولین کاراکتر غیرخالی
    const firstChar = val[0];

    if (firstChar.match(/[0-9]/)) {
      textarea.style.direction = "ltr"; // عدد، چپ‌چین
    } else if (firstChar.match(/[\u0600-\u06FF]/)) {
      textarea.style.direction = "rtl"; // فارسی/عربی، راست‌چین
    } else if (firstChar.match(/[a-zA-Z]/)) {
      textarea.style.direction = "ltr"; // انگلیسی، چپ‌چین
    } else {
      textarea.style.direction = "ltr"; // پیش‌فرض چپ‌چین
    }
  });
});

const outputTextarea = document.getElementById("output");

if (outputTextarea) {
  function copyToClipboard() {
    outputTextarea.select();
    outputTextarea.setSelectionRange(0, 99999); // For mobile devices

    try {
      const successful = document.execCommand("copy");
      if (successful) {
        alert("متن کپی شد!");
      } else {
        alert("کپی ناموفق بود");
      }
    } catch (err) {
      alert("مرورگر شما از کپی پشتیبانی نمی‌کند");
    }

    // برای خروج از حالت انتخاب متن:
    window.getSelection().removeAllRanges();
  }

  outputTextarea.addEventListener("click", copyToClipboard);
  outputTextarea.addEventListener("touchstart", copyToClipboard);
}

const passwordInput = document.getElementById("passwordInput");
const togglePassword = document.getElementById("togglePassword");
const eyeIcon = document.getElementById("eyeIcon");
const eyeSlashIcon = document.getElementById("eyeSlashIcon");

// togglePassword.addEventListener("click", () => {
//   if (passwordInput.type === "password") {
//     passwordInput.type = "text";
//     eyeIcon.classList.add("hidden");
//     eyeSlashIcon.classList.remove("hidden");
//   } else {
//     passwordInput.type = "password";
//     eyeIcon.classList.remove("hidden");
//     eyeSlashIcon.classList.add("hidden");
//   }
// });

// بروزرسانی آیکون‌ها بر اساس وضعیت فعلی input
function updateIcons() {
  if (passwordInput.type === "password") {
    // اگر رمز قابل مشاهده است، باید آیکون "چشم" نشون داده بشه
    eyeIcon.classList.remove("hidden");
    eyeSlashIcon.classList.add("hidden");
  } else {
    // اگر رمز پنهان است، آیکون چشم‌خط‌خورده بیاد
    eyeIcon.classList.add("hidden");
    eyeSlashIcon.classList.remove("hidden");
  }
}

// وقتی روی دکمه کلیک شد، حالت رمز تغییر کنه
togglePassword.addEventListener("click", () => {
  passwordInput.type = passwordInput.type === "password" ? "text" : "password";
  updateIcons(); // آیکون‌ها هم با تغییر هماهنگ بشن
});

// هنگام لود اولیه، آیکون مناسب رو نشون بده
updateIcons();

document.querySelector("form").addEventListener("submit", function (e) {
  e.preventDefault();
  // اجرای عملیات رمزنگاری
});

function generateSecureKey(length = 32) {
  const array = new Uint8Array(length);
  window.crypto.getRandomValues(array);
  return Array.from(array, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

document.querySelector(".startGenerateSafePrivateKey").addEventListener("click", (e) => {
  e.preventDefault();
  document.querySelector(".generateSafePrivateKey").value = generateSecureKey();
  document.querySelector(".generateSafePrivateKey").classList.add("text-left");
  document.querySelector(".generateSafePrivateKey").classList.add("consolas");
});
const copyButton = document.getElementById("copyButton");
const copyAlert = document.getElementById("copyAlert");

copyButton.addEventListener("click", () => {
  navigator.clipboard.writeText(passwordInput.value).then(() => {
    // نمایش اعلان
    copyAlert.classList.remove("opacity-0", "pointer-events-none");
    // مخفی کردن بعد از 2 ثانیه
    setTimeout(() => {
      copyAlert.classList.add("opacity-0", "pointer-events-none");
    }, 2000);
  });
});
