package implementation;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

public class SubjectInfo {
	
	private String country;
	private String state;
	private String locality;
	private String organization;
	private String orgUnit;
	private String commonName;

	public SubjectInfo() {
		super();
	}

	public static SubjectInfo parse(String inputString){
		// remove whitespaces
		inputString = inputString.replaceAll("\\s+", "");
		String[] arguments = inputString.split(",");

		SubjectInfo parsedSubjectInfo = new SubjectInfo();


		for(String arg: arguments){
			String[] keyInfo = arg.split("=");

			// if is set argument
			if(keyInfo.length == 2) {
				if ("C".equals(keyInfo[0])) {
					parsedSubjectInfo.country = keyInfo[1];
				} else if ("ST".equals(keyInfo[0]))
					parsedSubjectInfo.state = keyInfo[1];
				else if ("L".equals(keyInfo[0]))
					parsedSubjectInfo.locality = keyInfo[1];
				else if ("OU".equals(keyInfo[0]))
					parsedSubjectInfo.orgUnit = keyInfo[1];
				else if ("CN".equals(keyInfo[0]))
					parsedSubjectInfo.commonName = keyInfo[1];
				else if ("O".equals(keyInfo[0]))
					parsedSubjectInfo.organization = keyInfo[1];
			}
		}

		return parsedSubjectInfo;
	}

	public static X500Name getName(String subject) {
		SubjectInfo subjectInfo = parse(subject);
		X500NameBuilder ret = new X500NameBuilder();

		HashMap<ASN1ObjectIdentifier, String> map = new HashMap<>();

		map.put(BCStyle.CN, subjectInfo.getCommonName());
		if(subjectInfo.getOrganization() != null) map.put(BCStyle.O, subjectInfo.getOrganization());
		if(subjectInfo.getOrgUnit() != null) map.put(BCStyle.OU, subjectInfo.getOrgUnit());
		if(subjectInfo.getLocality() != null) map.put(BCStyle.L, subjectInfo.getLocality());
		if(subjectInfo.getState() != null) map.put(BCStyle.ST, subjectInfo.getState());
		if(subjectInfo.getCountry() != null) map.put(BCStyle.C, subjectInfo.getCountry());

		map.forEach((key, value) -> {
			if (!value.isEmpty()) {
				ret.addRDN(key, value);
			}
		});

		return ret.build();
	}




	public String getCountry() {
		return country;
	}
	public void setCountry(String country) {
		this.country = country;
	}
	public String getState() {
		return state;
	}
	public void setState(String state) {
		this.state = state;
	}
	public String getLocality() {
		return locality;
	}
	public void setLocality(String locality) {
		this.locality = locality;
	}
	public String getOrganization() {
		return organization;
	}
	public void setOrganization(String organization) {
		this.organization = organization;
	}
	public String getOrgUnit() {
		return orgUnit;
	}
	public void setOrgUnit(String orgUnit) {
		this.orgUnit = orgUnit;
	}
	public String getCommonName() {
		return commonName;
	}
	public void setCommonName(String commonName) {
		this.commonName = commonName;
	}
	
}
