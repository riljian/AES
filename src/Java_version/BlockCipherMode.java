abstract class BlockCipherMode{
	BlockCipherMode(String input){
		int len=input.length(), i;
		char[] str=input.toCharArray();
		for(i=0;i<block_size&&i<len;++i)
			key[i] = (int)str[i] & 0xFF;
	}
	BlockCipherMode(String input1, String input2){
		int len1=input1.length(), len2=input2.length(), i;
		char[] str1=input1.toCharArray(), str2=input2.toCharArray();
		for(i=0;i<block_size&&i<len1;++i)
			key[i] = (int)str1[i] & 0xFF;
		for(i=0;i<block_size&&i<len2;++i)
			IV[i] = (int)str2[i] & 0xFF;
	}
	int[] plainToIntArray(String input){
		int len=input.length(), i;
		int tmp=(len%8==0)?len:(len/8+1)*8;
		char[] str=input.toCharArray();
		int[] intArray=new int[tmp*2];
		for(i=0;i<len;++i){
			intArray[2*i] = (int)str[i] & 0xFF00;
			intArray[2*i+1] = (int)str[i] & 0xFF;
		}
		return intArray;
	}
	int[] cipherToIntArray(String input){
		int len=input.length(), i;
		int[] intArray=new int[len/2];
		for(i=0;i<len;i+=2)
			intArray[i/2] = Integer.parseInt(input.substring(i, i+2), 16);
		return intArray;
	}
	final int block_size=16;
	public abstract int[] encrypt(String input);
	public abstract char[] decrypt(String input);
	int[] key=new int[block_size], IV=new int[block_size];
}

class ECB extends BlockCipherMode{
	ECB(String input){
		super(input);
	}
	public int[] encrypt(String input){
		int i, j,len=input.length();
		len = ((len%8==0) ? len : (len/8+1)*8) * 2;
		int[] inputArray=plainToIntArray(input), tmp=new int[block_size];
		AES aes=new AES(key);
		for(i=0;i<len/block_size;++i){
			for(j=0;j<block_size;++j)
				tmp[j] = inputArray[i*block_size+j];
			aes.encrypt(tmp);
			for(j=0;j<block_size;++j)
				inputArray[i*block_size+j] = tmp[j];
		}
		return inputArray;
	}
	public char[] decrypt(String input){
		int len=input.length()/2, i, j;
		int[] inputArray=cipherToIntArray(input), tmp=new int[block_size];
		char[] plainText=new char[len/2];
		AES aes=new AES(key);
		for(i=0;i<len/block_size;++i){
			for(j=0;j<block_size;++j)
				tmp[j] = inputArray[i*block_size+j];
			aes.decrypt(tmp);
			for(j=0;j<block_size;++j)
				inputArray[i*block_size+j] = tmp[j];
		}
		for(i=0;i<len/2;++i)
			plainText[i] = (char)(inputArray[2*i] + inputArray[2*i+1]);
		return plainText;
	}
}

class CBC extends BlockCipherMode{
	CBC(String input1, String input2){
		super(input1, input2);
	}
	public int[] encrypt(String input){
		int i, j,len=input.length();
		len = ((len%8==0) ? len : (len/8+1)*8) * 2;
		int[] inputArray=plainToIntArray(input), tmp=new int[block_size];
		AES aes=new AES(key);
		for(i=0;i<len/block_size;++i){
			for(j=0;j<block_size;++j)
				tmp[j] = inputArray[i*block_size+j];
			if(i==0)
				for(j=0;j<block_size;++j)
					tmp[j] ^= IV[j];
			else
				for(j=0;j<block_size;++j)
					tmp[j] ^= inputArray[(i-1)*block_size+j];
			aes.encrypt(tmp);
			for(j=0;j<block_size;++j)
				inputArray[i*block_size+j] = tmp[j];
		}
		return inputArray;
	}
	public char[] decrypt(String input){
		int len=input.length()/2, i, j;
		int[] inputArray=cipherToIntArray(input), tmp=new int[block_size], tmp2=new int[block_size];
		char[] plainText=new char[len/2];
		AES aes=new AES(key);
		for(i=0;i<len/block_size;++i){
			for(j=0;j<block_size;++j)
				tmp[j] = inputArray[i*block_size+j];
			aes.decrypt(tmp);
			if(i==0)
				for(j=0;j<block_size;++j)
					tmp[j] ^= IV[j];
			else
				for(j=0;j<block_size;++j)
					tmp[j] ^= tmp2[j];
			for(j=0;j<block_size;++j){
				tmp2[j] = inputArray[i*block_size+j];
				inputArray[i*block_size+j] = tmp[j];
			}
		}
		for(i=0;i<len/2;++i)
			plainText[i] = (char)(inputArray[2*i] + inputArray[2*i+1]);
		return plainText;
	}
}

class OFB extends BlockCipherMode{
	OFB(String input1, String input2){
		super(input1, input2);
	}
	public int[] encrypt(String input){
		int i, j,len=input.length();
		len = ((len%8==0) ? len : (len/8+1)*8) * 2;
		int[] inputArray=plainToIntArray(input), tmp=new int[block_size];
		AES aes=new AES(key);
		for(i=0;i<block_size;++i)
			tmp[i] = IV[i];
		for(i=0;i<len/block_size;++i){
			aes.encrypt(tmp);
			for(j=0;j<block_size;++j)
				inputArray[i*block_size+j] ^= tmp[j];
		}
		return inputArray;
	}
	public char[] decrypt(String input){
		int len=input.length()/2, i, j;
		int[] inputArray=cipherToIntArray(input), tmp=new int[block_size];
		char[] plainText=new char[len/2];
		AES aes=new AES(key);
		for(i=0;i<block_size;++i)
			tmp[i] = IV[i];
		for(i=0;i<len/block_size;++i){
			aes.encrypt(tmp);
			for(j=0;j<block_size;++j)
				inputArray[i*block_size+j] ^= tmp[j];
		}
		for(i=0;i<len/2;++i)
			plainText[i] = (char)(inputArray[2*i] + inputArray[2*i+1]);
		return plainText;
	}
}
