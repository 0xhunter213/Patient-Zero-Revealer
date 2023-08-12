import React from 'react'
import {Button,Modal,ModalHeader,ModalBody,ModalFooter,Form,FormGroup,Label,Input,Col} from 'reactstrap';
import 'bootstrap/dist/css/bootstrap.min.css';

export default function ElasticConnection({modal,toggle,props}) {
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
            />
            </Col>
        </FormGroup>
        </Form>

    </ModalBody>
    <ModalFooter>
      <Button color='primary' onClick={toggle} outline>
        Connect
      </Button>{' '}
      <Button color="danger" onClick={toggle} outline>
        Cancel
      </Button>
    </ModalFooter>
    
  </Modal>
  )
}
