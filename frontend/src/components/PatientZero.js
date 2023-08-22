import React, { useState } from 'react'
import {Button,Modal,ModalHeader,ModalBody,ModalFooter,Form,FormGroup,Label,Input,Col} from 'reactstrap';
import 'bootstrap/dist/css/bootstrap.min.css';
import axios from 'axios';
import { API_URL,DEBUG } from '../constants';
export default function PatientZero({modal,toggle,props}) {
  const [username,setUsername] = useState(null);
  const [ip,setIp] = useState(null);
  const [date,setDate] = useState(null);
  
  const pzeroDetection = async ()=>{
    axios.post(`${API_URL[DEBUG]}pzero`,{
      username:username,
      ip_address:ip,
      timestamp:date
    }).then(
      res=>{
        let data = props.data;

        data.filter((val,id) => {
          if(id == res.data.id){
            val.infected_first = true;
          }
        });

        props.setData(data);
        
      }
    ).catch(
      e => {console.error(e)}
    );
    toggle();
  }
  return (
    <Modal isOpen={modal} toggle={toggle} {...props} fullscreen={"lg"} size='lg'> 
    <ModalHeader 
      toggle={toggle} 
      style={{
        "color":"#0457A6",
      }}
    >
    Patient Zero Detection
    </ModalHeader>
    <ModalBody>
        <Form>
            <FormGroup row>
                <Label
                for="Username"
                sm={2}
                >
                Username
                </Label>
                <Col sm={10}>
                <Input
                    id="Username"
                    name="Username"
                    placeholder="Username (required)"
                    type="Text"
                    onChange={(e)=> {setUsername(e.target.value)}}
                />
                </Col>
            </FormGroup>
            <FormGroup row>
                <Label
                for="ipaddress"
                sm={2}
                >
                Ip address                 
                </Label>
                <Col sm={10}>
                <Input
                    id="ipaddress"
                    name="ipaddress"
                    placeholder="ip address Ipv4 or Ipv6 (optional)"
                    type="Text"
                    onChange={(e)=>{setIp(e.target.value)}}
                />
                </Col>
            </FormGroup>
            <FormGroup row>
            <Label 
                for="Datetime"
                sm={2}
            >
            Datetime
            </Label>
            <Col sm={10}>
            <Input
            id="Datetime"
            name="datetime"
            placeholder="datetime 'YYYY-MM-DD HH:MM:SS:ZZZ' (optional)"
            type="datetime"
            onChange={(e)=>{setDate(e.target.value)}}
            />
            </Col>
        </FormGroup>
        </Form>

    </ModalBody>
    <ModalFooter>
      <Button color='primary' onClick={pzeroDetection} outline>
        Detect
      </Button>{' '}
      <Button color="danger" onClick={toggle} outline>
        Cancel
      </Button>
    </ModalFooter>
    
  </Modal>
  )
}
