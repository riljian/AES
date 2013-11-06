import java.io.*;
import java.util.*;

public class Main{
	public static void main(String[] args)throws IOException{
		BufferedReader in=new BufferedReader(new InputStreamReader(System.in));
		Scanner cin=new Scanner(System.in);
		BlockCipherMode encryptMode;
		int choice, len;
		if(args.length<3){
			System.out.println("Command: java Main [EncryptMode] [Key] [IV]");
			return;
		}
		if(args[0].trim().equals("ECB"))
			encryptMode = new ECB(args[1]);
		else if(args[0].trim().equals("CBC"))
			encryptMode = new CBC(args[1], args[2]);
		else if(args[0].trim().equals("OFB"))
			encryptMode = new OFB(args[1], args[2]);
		else{
			System.out.println("Command: java Main [EncryptMode] [Key] [IV]");
			return;
		}
		while(true){
			System.out.println("Please choose 1. Encrypt 2. Decrypt 3. Exit");
			choice = cin.nextInt();
			if(choice==1){
				System.out.println("Please input the plain text:");
				String plain=in.readLine();
				len = plain.length();
				len = ((len%8==0) ? len : (len/8+1)*8) * 2;
				int[] cipherIntArray=encryptMode.encrypt(plain);
				for(int i=0;i<len;++i)
					System.out.printf("%02x", cipherIntArray[i]);
				System.out.println("");
			}
			else if(choice==2){
				System.out.println("Please input the cipher text:");
				String cipher=in.readLine();
				System.out.println(encryptMode.decrypt(cipher));
			}
			else if(choice==3)
				return;
			else
				System.out.println("Please try again! (1-3)");
			System.out.println("");
		}
	}
}
