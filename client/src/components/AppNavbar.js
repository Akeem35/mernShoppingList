import React, { Component, Fragment } from 'react';
import {
  Collapse,
  Navbar,
  NavbarToggler,
  NavbarBrand,
  Nav,
  NavItem,
  NavLink,
  Container
} from 'reactstrap';

import RegisterModal from './auth/RegisterModal';
import LoginModal from './auth/LoginModal';
import Logout from './auth/Logout';
import { connect } from 'react-redux';
import PropTypes from 'prop-types';
import authReducer from '../reducers/authReducer';

class AppNavbar extends Component {
  state = {
    isOpen: false
  }

  static propTypes = {
    auth: PropTypes.object.isRequired
  }

  toggle = () => {
    this.setState({
      isOpen:!this.state.isOpen
    });
  }

  render() {
  const { isAuthenticated, user } = this.props.auth;

  const authLinks = (
    <Fragment>
      <NavItem>
        <RegisterModal />      
      </NavItem>
      <NavItem>
        <LoginModal />
      </NavItem>
    </Fragment>
  );

  const guestLinks = (
    <Fragment>
      <NavItem>
        <Logout />
      </NavItem>
    </Fragment>
  );

    return(
      <div>
        <Navbar color="dark" dark expand="sm" className="mb-5">
          <Container>
            <NavbarBrand href="/">Shopping List</NavbarBrand>>
            <NavbarToggler onClick={this.toggle} />
            <Collapse isOpen={this.state.isOpen} navbar>
              <Nav className="ml-auto" navbar>
                { isAuthenticated ? guestLinks : authLinks }
              </Nav>
            </Collapse>
          </Container>
        </Navbar>
      </div>
    );
  }
}

const mapStateToProps = state => ({
  auth: state.auth
});


export default connect(mapStateToProps, null)(AppNavbar);