package com.seec.spring.payload.response;

public class MensagemResponse {
	private String message;

	public MensagemResponse(String message) {
	    this.message = message;
	  }

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}
}
