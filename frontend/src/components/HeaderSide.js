import React from 'react'
import logo from "../assests/img/pz_logo.png"
import '../assests/css/HeaderSide.css';
const HeadersSide = (props)=> {
  return (
    <div className='title-logo'>
        <img src={logo}/>
        <p>P<span>Z</span>ero Revealer</p>
    </div>
  )
}

export default HeadersSide;
