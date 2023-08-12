import HeadersSide from './HeaderSide';
import React, { useEffect, useState } from 'react';
import "../assests/css/SideBar.css";
export default function SideBar() {
  const [data,setData] = useState([])
  window.addEventListener("storage",()=>{console.log("feching is good :"+sessionStorage.getItem("selected"))})
  var setVal = sessionStorage.getItem("set")
  const fun = async (setVal)=>{console.log("feching is good :"+setVal)}
  useEffect(()=>{fun(setVal)},[setVal])
  return (
    <div  className='sidebar'>
    <HeadersSide/>
    <p>{data}</p>
    </div>
  )
}
