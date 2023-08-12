import HeadersSide from './HeaderSide';
import React, { useEffect, useState } from 'react';
import "../assests/css/SideBar.css";
import { Collapse,CardBody, Card } from 'reactstrap';
import 'bootstrap/dist/css/bootstrap.min.css';

export default function SideBar({selected,setSelected,props}) {
  console.log("FROM SIDEBAR COMPENENT: ",selected);
  return (
    <div  className='sidebar'>
    <HeadersSide/>
      <div className='informations'>
      {selected.os == "Windows 10"?
      <Collapse isOpen={selected} >
        <Card>
          <CardBody>
        <h4>{selected.id}</h4>
        <div className='listInfos'>
          <br/>
          <br/>
          <br/>
          <tr>
          <td>
          <b>OS&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; &nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;</b>
          </td>
          <td>
          {selected.os}
          </td>
          </tr>
          <tr>
            <td><b>Build&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;</b></td>
            <td>{selected.build}</td>
          </tr>
          <tr>
            <td><b>Domain&nbsp;&nbsp;&nbsp;&nbsp;:</b></td>
            <td>{selected.domain}</td>
          </tr>
          <tr>
            <td><b>Ip Address &nbsp;&nbsp;&nbsp;&nbsp;:</b></td>
            <td>{selected.ip}</td>
          </tr>
          
        </div>
        </CardBody>
        </Card>
        </Collapse>
        :<></>}
      </div>  
    </div>
    
  )
}
