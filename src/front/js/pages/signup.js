import React, { useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'

export const Signup = () => {
  const [signup, setSignup] = useState({
    email: '',
    password: ''
  })

  const signupNewUser = async (formSignup) => {
    const url = "https://opulent-waddle-69vx96x494973xrwr-3001.app.github.dev/"
    const signupRequirement = "/api/signup"
    try {
      const response = await fetch(url + signupRequirement, {
        method: "POST",
        body: JSON.stringify(formSignup),
        headers: {
          'Content-type': 'application/json'
        },
      })
      if (response.ok) {
        const jsonResponse = await response.json()
        console.log(jsonResponse)
      } else {
        const jsonResponse = await response.json()
        console.log(jsonResponse)
      }
    } catch (e) {
      console.log("An error has occured", e)
    }
  }
  const goToLogin = useNavigate()
  const formRef = useRef(null)
  const handleInputForm = (value, name) => {
    setSignup({ ...signup, [name]: value })
  }
  const handleSubmit = async () => {
    try {
      console.log(signup)
      await signupNewUser(signup)
      alert(`The user was created successfully!`)
      formRef.current.reset()
      setSignup({
        email: '',
        password: ''
      })
      goToLogin("/login")
    } catch (e) {
      console.log("An error occurred, check it out", e)
    }
  }
  
  return (
    <div className='container-form'>
      <form
        ref={formRef}
        id='contact-form'
        className='form-signup'
        onSubmit={(e) => { e.preventDefault(); handleSubmit(); }}>
        <h6>Signup</h6>
        <label className='label-signup' htmlFor="email">Email:</label>
        <input
          className='input-signup'
          type="email"
          id="email"
          name="email"
          onChange={(e) => handleInputForm(e.target.value, e.target.name)}
          required
          value={signup.email}
        />
        <label className='label-signup' htmlFor="password">Password:</label>
        <input
          className='input-signup'
          type="password"
          id="password"
          name="password"
          onChange={(e) => handleInputForm(e.target.value, e.target.name)}
          required
          value={signup.password}
        />
        <button className="button-signup" type="submit">Sign Up</button>
      </form>
      <div className='goHome-login'>
        <Link to="/">Go Home</Link>
      </div>
    </div>
  )
}