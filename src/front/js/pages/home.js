import React, { useContext } from "react";
import { Context } from "../store/appContext";
import rigoImageUrl from "../../img/rigo-baby.jpg";
import "../../styles/home.css";
import { Link } from 'react-router-dom';

export const Home = () => {
	const { store, actions } = useContext(Context);

	return (
		<div className="text-center mt-5">
			<h1 className="mb-2">Homepage</h1>
			<Link to="/signup">
					<button className="btn btn-primary me-2">Sign-up</button>
			</Link>
			<Link to="/login">
					<button className="btn btn-primary">Login</button>
			</Link>
		</div>
	);
};