$(document).ready(function() {
	$("#home a:contains('Home')").parent().addClass('active');
	$("#clients a:contains('Clients')").parent().addClass('active');
	$("#contacts a:contains('Contacts')").parent().addClass('active');
	$("#employees a:contains('Employees')").parent().addClass('active');
	$("#findings a:contains('Findings')").parent().addClass('active');
	$("#projects a:contains('Projects')").parent().addClass('active');
	$("#hostvulns a:contains('Vulnerabilities')").parent().addClass('active');
	$("#webvulns a:contains('Vulnerabilities')").parent().addClass('active');
});
