<template>
  <div class="container">
    <transition name="slide" mode="out-in">
      <notification type="is-danger" @closeNotif="close()" v-if="errored">
        {{ errorMessage }}
      </notification>
    </transition>

    <transition name="slide" mode="out-in">
      <notification
        type="is-warning"
        @closeNotif="closeWarning"
        v-if="emailConfirmationPrompt"
      >
        {{ confirmationWarning }}
      </notification>
    </transition>
    <form novalidate="true" class="form" @submit.prevent="handleSubmit">
      <h1 class="signin">Sign In</h1>
      <div
        class="input-container"
        :class="{
          valid: !$v.username.$invalid,
          'not-valid': $v.username.$error
        }"
      >
        <label for="username">Username</label>
        <input
          v-focus
          required
          class="entry"
          id="username"
          type="text"
          v-model.trim="username"
          placeholder="e.g. John123"
          autocomplete="username"
        />
        <div v-show="$v.username.$dirty">
          <span v-show="!$v.username.required" class="error"
            >Username is required</span
          >
        </div>
      </div>
      <div
        class="input-container"
        :class="{
          valid: !$v.password.$invalid,
          'not-valid': $v.password.$error
        }"
      >
        <label for="password">Password</label>
        <div>
          <input
            required
            class="entry"
            id="password"
            :type="showPassword ? 'text' : 'password'"
            v-model.trim="password"
            placeholder="Password"
            autocomplete="current-password"
          />

          <button
            class="show-hide"
            @click.prevent="showPassword = !showPassword"
          >
            <svg
              v-if="showPassword"
              key="show-toggle"
              width="24"
              height="24"
              viewBox="0 0 24 24"
            >
              <path d="M0 0h24v24H0z" fill="none" />
              <path
                d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"
              />
            </svg>
            <svg
              v-else
              key="show-toggle"
              width="24"
              height="24"
              viewBox="0 0 24 24"
            >
              <path
                d="M0 0h24v24H0zm0 0h24v24H0zm0 0h24v24H0zm0 0h24v24H0z"
                fill="none"
              />
              <path
                d="M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.43-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z"
              />
            </svg>
          </button>
        </div>
        <div v-show="$v.password.$dirty">
          <span v-show="!$v.password.required" class="error"
            >Password is required</span
          >
        </div>
      </div>
      <button class="login" type="submit">Sign In</button>
      <h3 class="forgot">
        <router-link to="/forgot_password" class="has-text-link"
          >Forgot password?</router-link
        >
      </h3>
    </form>
    <h3 class="not-member ">
      Not a member?
      <router-link to="/signup" class="has-text-link">Sign up</router-link>
    </h3>
  </div>
</template>

<script>
import { required, email, minLength, helpers } from "vuelidate/lib/validators";
import Notification from "@/components/elements/Notification";
import axios from "axios";
import { store } from "../../store.js";

const usernameValid = helpers.regex("username", /^[a-zA-Z0-9]{1,20}$/);

export default {
  data() {
    return {
      username: "",
      password: "",
      showPassword: false,
      errored: false,
      errorMessage: "",
      confirmationWarning:
        "Confirm your email by clicking the verification link we just sent to your inbox.",
      emailConfirmationPrompt: false
    };
  },
  components: {
    notification: Notification
  },
  mounted() {
    if (this.$route.query.confirm) {
      this.emailConfirmationPrompt = true;
    }
  },
  methods: {
    handleSubmit() {
      this.$v.$touch();
      if (this.$v.$invalid) {
        this.errored = true;
        this.errorMessage =
          "Please correct all highlighted errors and try again";
      } else {
        axios
          .post(
            "/api/auth/login",
            {
              username: this.username,
              password: this.password
            },
          )
          .then(response => {
            this.errored = false;
            if (this.$cookie.get("JWTCookie") !== null) {
              if (this.$route.params.nextUrl != null) {
                this.$router.push(this.$route.params.nextUrl);
              } else {
                this.$router.push("/");
              }
            }
          })
          .catch(error => {
            this.errored = true;
            this.errorMessage = error.response.data.verbose_msg;
          });
      }
    },
    close() {
      this.errored = false;
    },
    closeWarning() {
      this.emailConfirmationPrompt = false
    }
  },
  validations: {
    username: {
      required,
      usernameValid
    },
    password: {
      required
    }
  }
};
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style lang="scss" scoped>
.not-valid {
  input {
    background: url("../../assets/imgs/error.svg") !important;
    background-repeat: no-repeat !important;
    background-position: 97% center !important;
    border: 1px solid #bb0000 !important;
  }
  .show-hide {
    border-color: #bb0000 !important;
  }
}

.container {
  margin-bottom: 4em;
}
.form {
  display: grid;
  line-height: 2em;
  align-items: center; /* align-self every label item vertically in its row!*/
  justify-content: center;
  width: 100%;
  grid-row-gap: 0.1em;
  padding: 4em;
  color: #333333;
  background-color: white;
  font-size: 16px;
  border-radius: 0.25rem;
  border: 1px solid #33333330;
}

.input-container {
  display: flex;
  height: 100px;
  flex-direction: column;
}
.input-container > div {
  width: 340px;
  display: flex;
  flex-direction: row;
}

.input-container:hover,
.input-container:focus-within {
  .show-hide,
  .entry {
    border-color: #3333336b;
    outline: none;
  }
}

.input-container > div > input {
  border-radius: 0.25rem 0 0 0.25rem !important;
  border-right: 0 !important;
}

.show-hide {
  width: 12%;
  background: none;
  border-radius: 0 0.25rem 0.25rem 0;
  border-width: 1px 1px 1px 0;
  border-style: solid;
  border-color: #33333335;
  box-shadow: inset -6px 2px 4px 0 hsla(0, 0%, 0%, 0.03);
}

.show-hide > svg {
  fill: #33333380;
}

.error {
  font-size: 0.8em;
  color: #bb0000;
  font-weight: 100;
}

.forgot,
.signin {
  margin: auto;
}

.signin {
  font-size: 2em;
  margin-bottom: 1em;
}

.not-member {
  font-size: 16px;
  text-align: center;
}

.form .entry {
  width: 340px;
  min-height: 45px;
  color: #333333;
  background: none;
  border: 1px solid #33333335;
  padding: 0.5em;
  font-size: inherit;
  border-radius: 0.25rem;
  box-shadow: inset 6px 2px 4px 0 hsla(0, 0%, 0%, 0.03);
  transition: border 0.1s ease;
}

.form .entry:focus {
  outline: none;
}

.login {
  cursor: pointer;
  border-radius: 0.25rem;
  font-size: inherit;
  padding: 0.7em;
  font-weight: 600;
  color: white;
  background-color: #e7501d;
  border: none;
  margin-top: 1em;
}

.form label {
  font-weight: 600;
}
</style>