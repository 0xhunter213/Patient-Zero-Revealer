import React, { useState } from 'react'
import {Button,Modal,ModalHeader,ModalBody,ModalFooter,Form,FormGroup,Label,Input,Col} from 'reactstrap';
import 'bootstrap/dist/css/bootstrap.min.css';
import axios from "axios";
import {API_URL,DEBUG } from "../constants";
export default function ElasticConnection({modal,toggle,props}) {
  const [key,setKey] = useState();
  const [user,setUser] = useState();
  const [pwd,setPwd] = useState();
  const [succ,setSucc] = useState(false);

  const elasticConfig = async () => {
    await axios.post(`${API_URL[DEBUG]}elastic`,{
      id:1,
      apikey:key,
      username:user,
      password:pwd
    }).then((response) => console.log(response.data) ).catch(
      e=>console.log(e)
    )
  }
  return (
    <Modal isOpen={modal} toggle={toggle} {...props} fullscreen={"xl"} size='xl'> 
    <ModalHeader 
      toggle={toggle} 
      style={{
        "color":"#0457A6",
      }}
    >
    Elastic Connection Settings
    </ModalHeader>
    <ModalBody>
        <Form>
            <FormGroup row>
                <Label
                for="cloudid"
                sm={2}
                >
                Cloud ID / API key
                </Label>
                <Col sm={10}>
                <Input
                    id="cloudid"
                    name="Cloud"
                    placeholder="Cloud Id or API key for elasticsearch server"
                    type="Text"
                    onChange={(e)=> {setKey(e.target.value)}}
                />
                </Col>
            </FormGroup>
            <FormGroup row>
                <Label
                for="username"
                sm={2}
                >
                Elastic User         
                </Label>
                <Col sm={10}>
                <Input
                    id="username"
                    name="Username"
                    placeholder="Elasticsearch username for api"
                    type="Text"
                    onChange={e => {setUser(e.target.value)}}
                />
                </Col>
            </FormGroup>
            <FormGroup row>
            <Label 
                for="password"
                sm={2}
            >
            Password
            </Label>
            <Col sm={10}>
            <Input
            id="password"
            name="Password"
            placeholder="Elasticsearch user password"
            type="password"
            onChange={e => {setPwd(e.target.value)}}
            />
            </Col>
        </FormGroup>
        </Form>

    </ModalBody>
    <ModalFooter>
      <Button color='primary' onClick={()=>{elasticConfig();}} outline>
        Connect
      </Button>{' '}
      <Button color="danger" onClick={toggle} outline>
        Cancel
      </Button>
    </ModalFooter>
    
  </Modal>
  )
}
