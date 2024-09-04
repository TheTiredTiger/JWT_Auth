import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
export const Login = () => {
    
    const navigate = useNavigate();
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [error, setError] = useState("");


    const loginUserExisting = async ({ email, password }) => {
        const url = "https://opulent-waddle-69vx96x494973xrwr-3001.app.github.dev/";
        const loginRequirement = "/api/login";
        try {
            const response = await fetch(url + loginRequirement, {
                method: 'POST',
                headers: {
                    'Content-type': 'application/json'
                },
                body: JSON.stringify({
                    email,
                    password
                })
            });
            console.log('Response status:', response.status);
            if (response.status !== 200) {
                throw new Error(`Invalid response status: ${response.status}`);
            }
            const jsonResponse = await response.json();
            console.log('JSON Response:', jsonResponse);
            if (jsonResponse.token) {
                localStorage.setItem("access_token", jsonResponse.token);
                return true;
            } else {
                console.warn('No token found in response');
                return false;
            }
        } catch (e) {
            console.error("An error occurred:", e);
            throw e;
        }
    };
    
    
    
    
    
    



    const handleSubmit = async (event) => {
        event.preventDefault(); // Prevent default form submission behavior
        try {
            const loginSuccessful = await loginUserExisting({ email, password });
            if (loginSuccessful) {
                navigate("/private");
            } else {
                setError("User or password incorrect");
                setEmail("");
                setPassword("");
            }
        } catch (error) {
            setError("An error occurred during login");
            console.error(error);
        }
    };
    return (
        <div className='container-form'>
            <form id='contact-form' className='form-signup' onSubmit={handleSubmit}>
                <h6>Login</h6>
                <label className='label-signup' htmlFor="email">Email:</label>
                <input className='input-signup' type="email" id="email" name="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
                <label className='label-signup' htmlFor="password">Password:</label>
                <input className='input-signup' type="password" id="password" name="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
                <button className="button-signup" type="submit">Login</button>
            </form>
            {error && <p>{error}</p>}
            <div className='goHome-login'>
                <Link to="/">Go Home</Link>
            </div>
        </div>
    );
};