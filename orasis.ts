import {
  BadRequestException,
  ConfigurableModuleBuilder,
  HttpException,
  HttpStatus,
  Injectable,
  InternalServerErrorException,
} from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import { TokenAllocation, MerkleRoot } from "./token.model";
import { GenerateMerkleTreeService } from "src/shared/utils/generate-merkle-tree";
import * as csv from "csv-parser";
import * as fs from "fs";
import * as path from "path";
import Moralis from "moralis";
import { EvmChain } from "@moralisweb3/common-evm-utils";
import { LoginInputDto } from "./dtos/login-input.dto";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";
import { ResponseHandlerService } from "src/shared/response/response-handler.service";
import { Web3Instance } from "src/shared/web3/web3.setup";
import { MESSAGES } from "src/shared/response/messages";
import { TOKEN_ALLOCATION_ABI } from "src/shared/abi/TokenAllocationABI";
let Web3 = require("web3");
const crypto = require("crypto");
const keccak256 = require("keccak256");

@Injectable()
export class TokenService {
  constructor(
    @InjectModel("TokenAllocation")
    private readonly tokenAllocationModel: Model<TokenAllocation>,
    @InjectModel("MerkleRoot")
    private readonly merkleRootModel: Model<MerkleRoot>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private responseHandler: ResponseHandlerService,
    private web3Instance: Web3Instance,
    private generateMerkleTreeService: GenerateMerkleTreeService
  ) {}

  async login(loginDto: LoginInputDto) {
    const { signatureMessage, signature } = loginDto;
    const address = loginDto.address.toLowerCase();
    const endpoint = this.configService.get("POLYGON_ENDPOINT");
    const instance = this.web3Instance.getInstance();

    const contract = new instance.eth.Contract(
      TOKEN_ALLOCATION_ABI,
      this.configService.get("CONTRACT_ADDRESS")
    );

    const decodedAddress = instance.eth.accounts.recover(
      signatureMessage,
      signature
    );
    console.log("decodedAddress", decodedAddress);
    console.log("address", address);

    const isOwner = await contract.methods.owners(address).call();
    if (address !== decodedAddress.toLowerCase() || !isOwner) {
      await this.responseHandler.response(
        MESSAGES.EN.INVALID_LOGIN,
        HttpStatus.UNAUTHORIZED,
        null
      );
    }

    const payload = { address };
    const refreshToken = this.jwtService.sign(payload, {
      expiresIn: this.configService.get("REFRESH_TOKEN_EXPIRY_TIME"),
    });

    const accessToken = this.jwtService.sign(payload);

    return {
      accessToken,
      refreshToken,
    };
  }
  async refreshAccessToken(refreshToken: string) {
    try {
      const decoded = this.jwtService.verify(refreshToken);
      const payload = { address: decoded.address };
      const accessToken = this.jwtService.sign(payload);
      console.log("accessToken", accessToken);

      return { accessToken };
    } catch (error) {
      await this.responseHandler.response(
        MESSAGES.EN.INVALID_REFRESH_TOKEN,
        HttpStatus.UNAUTHORIZED,
        null
      );
    }
  }
  async getUserDetails(address: string, category: string) {
    const user = await this.tokenAllocationModel.findOne({ address, category });
    if (!user)
      return await this.responseHandler.response(
        MESSAGES.EN.USER_NOT_FOUND,
        HttpStatus.BAD_REQUEST,
        null
      );
    else {
      return {
        totalAllocatedTokens: user.tokens_allocated,
        vestingDetails: {
          startTimestamp: user.vesting_start_time,
          cliffPeriod: user.cliff_period,
          vestingPeriod: user.vesting_period,
        },
      };
    }
  }
  async userMerkleProof(address: string, category: string) {
    const merkleProof = await this.getHexProof(address, category);

    if (!merkleProof.merkleProof)
      return await this.responseHandler.response(
        MESSAGES.EN.USER_NOT_FOUND,
        HttpStatus.BAD_REQUEST,
        null
      );
    return merkleProof;
  }

  async getClaimableTokens(user: TokenAllocation, tillTimestamp: number) {
    const {
      vesting_start_time,
      vesting_period,
      claimable_frequency,
      tokens_allocated,
    } = user;
    const timeElapsed = tillTimestamp - vesting_start_time;
    console.log("timeElapsed, claim", timeElapsed, claimable_frequency);
    const claimedTokens = await this.getAlreadyClaimedTokens(
      user.address,
      user.category
    );
    const totalClaimable =
      (Math.floor(timeElapsed / claimable_frequency) * tokens_allocated) /
        vesting_period -
      claimedTokens;

    console.log("totalClaimable", totalClaimable);

    return totalClaimable;
  }
  async getAlreadyClaimedTokens(address: string, category: string) {
    //logic to get data from smart contract
    return 0;
  }

  async toggleBlacklist(address: string, category: string, blacklist: boolean) {
    let blacklisted_timestamp;
    if (blacklist === false) blacklisted_timestamp = 0;
    else blacklisted_timestamp = Math.floor(Date.now() / 1000);

    console.log("blacklisted_timestamp", blacklisted_timestamp);

    const user = await this.tokenAllocationModel.findOneAndUpdate(
      { address, category },
      {
        blacklisted: blacklist,
        blacklisted_timestamp,
      },
      { new: true }
    );
    console.log(user);
    if (user) return { success: true };
    else
      await this.responseHandler.response(
        MESSAGES.EN.USER_NOT_FOUND,
        HttpStatus.BAD_REQUEST,
        null
      );
  }

  async removeVesting(address: string, category: string) {
    const user = await this.tokenAllocationModel.findOneAndUpdate(
      { address, category },
      { removed: true },
      { new: true }
    );
    console.log(user);
    if (user) return { success: true };
    else
      await this.responseHandler.response(
        MESSAGES.EN.USER_NOT_FOUND,
        HttpStatus.BAD_REQUEST,
        null
      );
    return { status: "success" };
  }
  async getTokenAllocation(address: string, category: string) {
    const tokens_allocated = await this.tokenAllocationModel.findOne(
      {
        address,
        category,
      },
      { _id: 0, tokens_allocated: 1 }
    );
    return tokens_allocated ? tokens_allocated : { tokens_allocated: null };
  }

  async addTokenAllocation(
    address: string,
    tokensAllocated: number,
    vestingStartTime: number,
    vestingPeriod: number,
    claimableFrequency: number,
    category: string
  ) {
    const newTokenAllocation = new this.tokenAllocationModel({
      address,
      tokensAllocated,
      vestingStartTime,
      vestingPeriod,
      claimableFrequency,
      category,
    });
    return await newTokenAllocation.save();
  }

  async addTokenThroughCSV(file, category) {
    const results = [];

    // Parse CSV file and convert to JSON
    const filePath = path.join(process.cwd(), "uploads", file.filename);
    let merkleRoot = {};

    await new Promise<void>((resolve, reject) => {
      fs.createReadStream(filePath)
        .pipe(
          csv({
            skipLines: 1,
            headers: [
              "address",
              "vesting_start_time",
              "vesting_end_time",
              "cliff_period",
              "claimable_frequency",
              "tokens_allocated",
            ],
          })
        )
        .on("data", (data) => {
          // Check if all values are empty and skip those lines
          if (Object.values(data).every((value: string) => !value.trim())) {
            return;
          }
          // Convert string to number
          data.tokens_allocated = parseFloat(data.tokens_allocated);
          data.vesting_start_time = parseFloat(data.vesting_start_time);

          // Check if vesting_period is a number
          if (
            !isNaN(data.vesting_end_time) &&
            !isNaN(data.vesting_start_time)
          ) {
            // converting vesting period to months
            data.vesting_period = Math.floor(
              (parseFloat(data.vesting_end_time) - data.vesting_start_time) /
                2592000
            );
          }

          data.claimable_frequency = parseFloat(data.claimable_frequency);
          data.cliff_period = parseFloat(data.cliff_period);
          data.category = category;
          results.push(data);
        })
        .on("end", async () => {
          const totalTokensUploaded = results.reduce(
            (acc, curr) => acc + curr.tokens_allocated,
            0
          );
          const tokenLimit = await this.merkleRootModel.findOne(
            { category },
            { _id: 0, total_tokens_limit: 1 }
          );
          try {
            if (!tokenLimit) {
              return await this.responseHandler.response(
                MESSAGES.EN.CATERGORY_NOT_FOUND,
                HttpStatus.BAD_REQUEST,
                null
              );
            }
            if (totalTokensUploaded > tokenLimit.total_tokens_limit) {
              await this.responseHandler.response(
                MESSAGES.EN.TOKEN_LIMIT_EXCEEDED,
                HttpStatus.BAD_REQUEST,
                null
              );
            }

            // Update or insert documents using upserting
            for (const result of results) {
              const { address, category } = result;
              const filter = { address, category };
              const update = { $set: result };
              const options = { upsert: true };
              await this.tokenAllocationModel.updateOne(
                filter,
                update,
                options
              );
            }

            console.log("Data inserted/updated in db successfully");

            // Delete CSV file
            fs.unlinkSync(filePath);
            merkleRoot = await this.updateMerkleRoot(category);
            resolve();
          } catch (e) {
            reject(e);
          }
        })
        .on("error", (error) => {
          reject(error);
        });
    });

    return merkleRoot;
  }

  async getMerkleTree(category) {
    let tokenAllocations = await this.tokenAllocationModel.find(
      { category },
      { _id: 0, address: 1, tokens_allocated: 1 }
    );

    const data = tokenAllocations.map((allocation) => [
      allocation.address,
      allocation.tokens_allocated,
    ]);
    console.log("Data in the merkle tree", data);

    const merkletree = this.generateMerkleTreeService.generateMerkleTree(data);
    return merkletree;
  }
  async updateMerkleRoot(category) {
    const merkletree = await this.getMerkleTree(category);
    const merkleRoot = merkletree.getHexRoot();
    const merkleRootForCategory = await this.merkleRootModel.findOne({
      category,
    });
    if (merkleRootForCategory) {
      merkleRootForCategory.merkle_root = merkleRoot;
      await merkleRootForCategory.save();
    } else {
      const newMerkleRootForCategory = new this.merkleRootModel({
        category,
        merkle_root: merkleRoot,
      });
      await newMerkleRootForCategory.save();
    }
    console.log(
      "Merkle root updated successfully for ",
      category,
      ":",
      merkleRoot
    );
    return { merkleRoot };
  }

  async getHexProof(address: string, category: string) {
    const merkleRoot = await this.merkleRootModel.findOne({ category });
    const tokenAllocated = await this.tokenAllocationModel.findOne(
      {
        address,
        category,
      },
      { _id: 0, tokens_allocated: 1 }
    );
    if (!merkleRoot || !tokenAllocated) {
      return { merkleProof: null };
    }

    const merkleTree = await this.getMerkleTree(category);
    const instance = this.web3Instance.getInstance();
    const encodedData = instance.utils.encodePacked(
      { type: "address", value: address },
      { type: "uint256", value: tokenAllocated.tokens_allocated }
    );
    const leafNode = keccak256(encodedData);
    const merkleProof = merkleTree.getHexProof(leafNode);

    // const res = merkleTree.verify(merkleProof, leafNode, merkleRoot.merkle_root);
    // console.log('Proof verified successfully:? ', res);

    return { merkleProof };
  }
}
