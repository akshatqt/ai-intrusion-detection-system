document.addEventListener("DOMContentLoaded", () => {
  console.log("[login] DOMContentLoaded - script.js loaded");

  // Get references to all required elements
  const loginForm = document.getElementById("loginForm");
  const emailInput = document.getElementById("email");
  const passwordInput = document.getElementById("password");
  const emailError = document.getElementById("emailError");
  const passwordError = document.getElementById("passwordError");
  const togglePasswordBtn = document.getElementById("togglePassword");
  const googleSignInBtn = document.getElementById("googleSignIn");

  console.log("[login] Elements:", {
    loginForm,
    emailInput,
    passwordInput,
    emailError,
    passwordError,
    togglePasswordBtn,
    googleSignInBtn,
  });

  if (!loginForm) {
    console.error("[login] loginForm not found in DOM");
    return;
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$/;

  function validateEmail(value) {
    if (!value) {
      return "Email is required";
    }
    if (!emailRegex.test(value.trim())) {
      return "Please enter a valid email address";
    }
    return "";
  }

  function validatePassword(value) {
    if (!value) {
      return "Password is required";
    }
    if (!passwordRegex.test(value)) {
      return "Password must have 8+ chars, upper, lower, number, special";
    }
    return "";
  }

  function showError(element, message) {
    if (!element) return;
    element.textContent = message;
  }

  function clearErrors() {
    showError(emailError, "");
    showError(passwordError, "");
  }

  // Inline validation on blur
  if (emailInput) {
    emailInput.addEventListener("blur", () => {
      const msg = validateEmail(emailInput.value);
      console.log("[login] Email blur validation:", msg || "OK");
      showError(emailError, msg);
    });
  }

  if (passwordInput) {
    passwordInput.addEventListener("blur", () => {
      const msg = validatePassword(passwordInput.value);
      console.log("[login] Password blur validation:", msg || "OK");
      showError(passwordError, msg);
    });
  }

  // Toggle password visibility
  if (togglePasswordBtn && passwordInput) {
    togglePasswordBtn.addEventListener("click", () => {
      const isPassword = passwordInput.type === "password";
      passwordInput.type = isPassword ? "text" : "password";
      const iconSpan = togglePasswordBtn.querySelector(".password-toggle-icon");
      if (iconSpan) {
        iconSpan.textContent = isPassword ? "🙈" : "👁";
      }
      console.log("[login] Toggled password visibility. Now type:", passwordInput.type);
    });
  }

  // Main login submit handler
  loginForm.addEventListener("submit", (event) => {
    event.preventDefault();
    console.log("[login] Submit handler fired");

    clearErrors();

    const emailValue = emailInput ? emailInput.value : "";
    const passwordValue = passwordInput ? passwordInput.value : "";

    console.log("[login] Submitted values:", { email: emailValue });

    const emailMessage = validateEmail(emailValue);
    const passwordMessage = validatePassword(passwordValue);

    let isValid = true;

    if (emailMessage) {
      showError(emailError, emailMessage);
      isValid = false;
    }

    if (passwordMessage) {
      showError(passwordError, passwordMessage);
      isValid = false;
    }

    console.log("[login] Validation result isValid=", isValid);
    if (!isValid) {
      return;
    }

    // Demo credentials (update if needed)
    const demoEmail = "admin@example.com";
    const demoPassword = "NeuralGuard!1";

    const isCorrect = emailValue.trim() === demoEmail && passwordValue === demoPassword;
    console.log("[login] Credentials correct?", isCorrect);

    if (isCorrect) {
      // Save login state and redirect to dashboard
      localStorage.setItem("loggedIn", "true");
      console.log("[login] Login successful. Redirecting to ../demo1/index.html");
      window.location.href = "../demo1/index.html";
    } else {
      console.log("[login] Invalid credentials entered");
      showError(passwordError, "Invalid credentials (demo: admin@example.com / NeuralGuard!1)");
    }
  });

  // Google Sign-in placeholder
  if (googleSignInBtn) {
    googleSignInBtn.addEventListener("click", () => {
      console.log("[login] Google Sign-In button clicked");
      alert(
        "Google Sign-In placeholder. Integrate Google Identity Services or Firebase Auth here."
      );
    });
  }
});
